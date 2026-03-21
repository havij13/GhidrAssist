package ghidrassist.services;

import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.chat.message.MessageRepository;
import ghidrassist.chat.message.MessageStore;
import ghidrassist.chat.message.ThreadSafeMessageStore;
import ghidrassist.chat.persistence.ChatHistoryDAO;
import ghidrassist.chat.persistence.ChatHistoryDAO.DocumentChatMetadata;
import ghidrassist.chat.persistence.SqliteTransactionManager;
import ghidrassist.chat.persistence.TransactionManager;
import ghidrassist.chat.session.ChatSession;
import ghidrassist.chat.session.ChatSessionManager;
import ghidrassist.chat.session.ChatSessionRepository;
import ghidrassist.chat.util.RoleNormalizer;
import ghidrassist.core.QueryProcessor;
import ghidrassist.mcp2.tools.MCPToolManager;
import ghidrassist.tools.native_.DocumentToolProvider;
import ghidrassist.tools.native_.NativeToolManager;
import ghidrassist.tools.registry.ToolRegistry;
import ghidrassist.graphrag.GraphRAGService;
import ghidrassist.services.symgraph.SymGraphModels.Document;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for handling custom queries and conversations.
 * Responsible for processing user queries, RAG integration, and conversation management.
 *
 * Refactored to use:
 * - MessageStore for thread-safe in-memory message storage (eliminates dual storage)
 * - ChatSessionManager for thread-safe session lifecycle
 * - ChatHistoryDAO for database operations
 * - RoleNormalizer for consistent role handling
 */
public class QueryService {
    private static final String CHAT_TYPE_CHAT = "chat";
    private static final String CHAT_TYPE_GENERAL = "general";
    private static final String CHAT_TYPE_MALWARE_REPORT = "malware_report";
    private static final String CHAT_TYPE_VULNERABILITY_ANALYSIS = "vuln_analysis";
    private static final String CHAT_TYPE_API_DOCUMENTATION = "api_doc";
    private static final String CHAT_TYPE_NOTES = "notes";
    private static final String DEFAULT_DOCUMENT_DOC_TYPE = "notes";

    private final GhidrAssistPlugin plugin;
    private final AnalysisDB analysisDB;  // Keep for ReAct and backward compatibility
    private final AnalysisDataService analysisDataService;
    private final ToolRegistry toolRegistry;

    // New architecture components
    private final MessageStore messageStore;
    private final ChatSessionManager sessionManager;
    private final MessageRepository messageRepository;
    private final ChatSessionRepository sessionRepository;
    private final ChatHistoryDAO chatHistoryDAO;
    private NativeToolManager nativeToolManager;

    public QueryService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.analysisDB = new AnalysisDB();
        this.analysisDataService = new AnalysisDataService(plugin);

        // Initialize tool registry with native tools
        this.toolRegistry = new ToolRegistry();
        try {
            this.nativeToolManager = new NativeToolManager(analysisDB);
            toolRegistry.registerProvider(nativeToolManager);
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "Failed to initialize native tools: " + e.getMessage());
        }

        // Initialize new architecture components
        TransactionManager transactionManager = new SqliteTransactionManager(analysisDB.getConnection());
        ChatHistoryDAO dao = new ChatHistoryDAO(transactionManager);

        this.messageStore = new ThreadSafeMessageStore();
        this.chatHistoryDAO = dao;
        this.messageRepository = dao;
        this.sessionRepository = dao;
        this.sessionManager = new ChatSessionManager(sessionRepository, messageRepository, messageStore);
    }

    // ==================== Query Request Creation ====================

    /**
     * Process a user query with optional RAG context (backwards compatibility)
     */
    public QueryRequest createQueryRequest(String query, boolean useRAG) throws Exception {
        return createQueryRequest(query, useRAG, false);
    }

    /**
     * Process a user query with optional RAG context and MCP integration
     */
    public QueryRequest createQueryRequest(String query, boolean useRAG, boolean useMCP) throws Exception {
        String processedQuery = QueryProcessor.processMacrosInQuery(query, plugin);

        if (useRAG) {
            try {
                processedQuery = QueryProcessor.appendRAGContext(processedQuery);
            } catch (Exception e) {
                throw new Exception("Failed to perform RAG search: " + e.getMessage(), e);
            }
        }

        // Add user message to message store and database
        addUserMessage(processedQuery, messageStore.getCurrentProviderType(), null);

        return new QueryRequest(processedQuery, messageStore.getFormattedConversation(), useMCP);
    }

    // ==================== Query Execution ====================

    /**
     * Execute a query request
     */
    public void executeQuery(QueryRequest request, LlmApi.LlmResponseHandler handler) throws Exception {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new Exception("No API provider configured.");
        }

        LlmApi llmApi = new LlmApi(config, plugin);

        // Apply saved reasoning config to the LlmApi
        ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
        if (currentProgram != null) {
            String programHash = currentProgram.getExecutableSHA256();
            String savedEffort = analysisDB.getReasoningEffort(programHash);
            if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                ghidrassist.apiprovider.ReasoningConfig reasoningConfig =
                        ghidrassist.apiprovider.ReasoningConfig.fromString(savedEffort);
                llmApi.setReasoningConfig(reasoningConfig);
            }
        }

        // Initialize GraphRAGService with LLM provider for background semantic analysis
        initializeGraphRAGService(config);

        executeQuery(request, llmApi, handler);
    }

    /**
     * Initialize GraphRAGService with LLM provider and current program context.
     * This enables background semantic analysis when queries trigger on-demand indexing.
     */
    private void initializeGraphRAGService(APIProviderConfig config) {
        try {
            GraphRAGService graphRAG = GraphRAGService.getInstance(analysisDB);

            // Set LLM provider for background semantic analysis
            if (config != null) {
                ghidrassist.apiprovider.APIProvider provider = config.createProvider();

                // Apply saved reasoning config to the new provider
                ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
                if (currentProgram != null) {
                    String programHash = currentProgram.getExecutableSHA256();
                    String savedEffort = analysisDB.getReasoningEffort(programHash);
                    if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                        ghidrassist.apiprovider.ReasoningConfig reasoningConfig =
                                ghidrassist.apiprovider.ReasoningConfig.fromString(savedEffort);
                        provider.setReasoningConfig(reasoningConfig);
                    }
                }

                graphRAG.setLLMProvider(provider);
            }

            // Set current program context
            ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
            if (currentProgram != null) {
                graphRAG.setCurrentProgram(currentProgram);
            }
        } catch (Exception e) {
            ghidra.util.Msg.warn(this, "Failed to initialize GraphRAGService: " + e.getMessage());
        }
    }

    /**
     * Execute a query request with provided LlmApi instance
     */
    public void executeQuery(QueryRequest request, LlmApi llmApi, LlmApi.LlmResponseHandler handler) throws Exception {
        if (request.shouldUseMCP()) {
            try {
                MCPToolManager toolManager = MCPToolManager.getInstance();

                if (!toolManager.isInitialized()) {
                    toolManager.initializeServers()
                        .thenRun(() -> {
                            try {
                                executeMCPQuery(request, llmApi, toolManager, handler);
                            } catch (Exception e) {
                                ghidra.util.Msg.warn(this, "MCP query execution failed: " + e.getMessage());
                                try {
                                    executeRegularQuery(request, llmApi, handler);
                                } catch (Exception e2) {
                                    ghidra.util.Msg.error(this, "Failed to execute regular query: " + e2.getMessage());
                                    handler.onError(e2);
                                }
                            }
                        })
                        .exceptionally(throwable -> {
                            ghidra.util.Msg.warn(this, "MCP initialization failed: " + throwable.getMessage());
                            try {
                                executeRegularQuery(request, llmApi, handler);
                            } catch (Exception e) {
                                handler.onError(e);
                            }
                            return null;
                        });
                    return;
                } else {
                    try {
                        executeMCPQuery(request, llmApi, toolManager, handler);
                        return;
                    } catch (Exception e) {
                        ghidra.util.Msg.warn(this, "MCP query failed, falling back: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                ghidra.util.Msg.warn(this, "MCP initialization failed: " + e.getMessage());
            }
        }

        // MCP is disabled, but native tools (semantics, etc.) should still be available
        executeNativeToolQuery(request, llmApi, handler);
    }

    /**
     * Execute a query with native tools only (no MCP tools).
     * Native tools include semantics analysis, knowledge graph queries, etc.
     */
    private void executeNativeToolQuery(QueryRequest request, LlmApi llmApi,
                                         LlmApi.LlmResponseHandler handler) throws Exception {
        // Set full context (program + address) for native tool providers
        ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
        ghidra.program.model.address.Address currentAddress = plugin.getCurrentAddress();
        if (currentProgram != null) {
            toolRegistry.setFullContext(currentProgram, currentAddress);
        } else {
            // No active binary context: fall back to plain chat mode.
            // Native tools depend on program/address and can cause incomplete
            // tool-calling loops when no program is loaded.
            ghidra.util.Msg.info(this, "No program context - using regular query mode (native tools disabled)");
            executeRegularQuery(request, llmApi, handler);
            return;
        }

        // Get native tools only (MCP tools won't be registered since MCP is disabled)
        java.util.List<java.util.Map<String, Object>> nativeFunctions = toolRegistry.getToolsAsFunction();

        ghidra.util.Msg.info(this, "Native tool registry has " + nativeFunctions.size() + " tools available");

        if (!nativeFunctions.isEmpty()) {
            // Plain Query mode: no artificial tool round limit.
            // The maxToolCalls setting only applies to ReAct iterations.
            int maxToolRounds = 500;

            // Get existing history with thinking data preserved for multi-turn conversations
            List<ChatMessage> fullHistory = messageStore.getMessagesForApi();
            List<ChatMessage> existingHistory;

            if (fullHistory == null || fullHistory.size() <= 1) {
                existingHistory = new ArrayList<>();
            } else {
                existingHistory = new ArrayList<>(fullHistory.subList(0, fullHistory.size() - 1));
            }

            // Use history-aware method to preserve thinking data across turns
            llmApi.sendConversationalToolRequestWithHistory(
                existingHistory,
                request.getProcessedQuery(),
                nativeFunctions,
                handler,
                maxToolRounds,
                toolRegistry
            );
        } else {
            // No native tools available, fall back to regular query
            executeRegularQuery(request, llmApi, handler);
        }
    }

    private void executeMCPQuery(QueryRequest request, LlmApi llmApi, MCPToolManager toolManager,
                                  LlmApi.LlmResponseHandler handler) throws Exception {
        // Register MCP tool manager with the tool registry (if not already registered)
        // This ensures both native and MCP tools are available
        if (!toolRegistry.hasProvider(toolManager.getProviderName())) {
            toolRegistry.registerProvider(toolManager);
        }

        // Set full context (program + address) for all tool providers
        ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
        ghidra.program.model.address.Address currentAddress = plugin.getCurrentAddress();
        if (currentProgram != null) {
            toolRegistry.setFullContext(currentProgram, currentAddress);
        }

        // Get ALL tools from registry (includes native tools + MCP tools)
        java.util.List<java.util.Map<String, Object>> allFunctions = toolRegistry.getToolsAsFunction();

        ghidra.util.Msg.info(this, "Tool registry has " + allFunctions.size() + " tools available");

        if (!allFunctions.isEmpty()) {
            // Plain MCP mode: no artificial tool round limit.
            // The maxToolCalls setting only applies to ReAct iterations.
            int maxToolRounds = 500;

            // Get existing history with thinking data preserved for multi-turn conversations
            // The current user message is already in the store, so get all PREVIOUS messages
            List<ChatMessage> fullHistory = messageStore.getMessagesForApi();
            List<ChatMessage> existingHistory;

            if (fullHistory == null || fullHistory.size() <= 1) {
                // No previous history or only the current user message - start fresh
                existingHistory = new ArrayList<>();
            } else {
                // Get all messages except the last one (current user message)
                // This preserves thinking data from previous assistant responses
                existingHistory = new ArrayList<>(fullHistory.subList(0, fullHistory.size() - 1));
            }

            // Use history-aware method to preserve thinking data across turns
            llmApi.sendConversationalToolRequestWithHistory(
                existingHistory,
                request.getProcessedQuery(),
                allFunctions,
                handler,
                maxToolRounds,
                toolRegistry
            );
        } else {
            executeRegularQuery(request, llmApi, handler);
        }
    }

    private void executeRegularQuery(QueryRequest request, LlmApi llmApi,
                                      LlmApi.LlmResponseHandler handler) throws Exception {
        llmApi.sendRequestAsync(request.getFullConversation(), handler);
    }

    // ==================== Message Management ====================

    /**
     * Add user query to conversation (legacy method)
     */
    public void addUserQuery(String query) {
        addUserMessage(query, messageStore.getCurrentProviderType(), null);
    }

    /**
     * Add user message with provider info
     */
    public void addUserMessage(String query, String providerType, ChatMessage apiMessage) {
        messageStore.addUserMessage(query, providerType, apiMessage);

        // Ensure session exists and save to database
        String programHash = getProgramHash();
        if (programHash != null) {
            int sessionId = sessionManager.ensureSession(programHash);
            if (sessionId != ChatSessionManager.NO_SESSION) {
                PersistedChatMessage msg = getLastMessage();
                if (msg != null) {
                    messageRepository.saveMessage(programHash, sessionId, msg);
                }
            }
        }
    }

    /**
     * Add assistant response (legacy method)
     */
    public void addAssistantResponse(String response) {
        addAssistantMessage(response, messageStore.getCurrentProviderType(), null);
    }

    /**
     * Add assistant message with provider info
     */
    public void addAssistantMessage(String response, String providerType, ChatMessage apiMessage) {
        messageStore.addAssistantMessage(response, providerType, apiMessage);

        // Save to database
        String programHash = getProgramHash();
        int sessionId = sessionManager.getCurrentSessionId();
        if (programHash != null && sessionId != ChatSessionManager.NO_SESSION) {
            PersistedChatMessage msg = getLastMessage();
            if (msg != null) {
                messageRepository.saveMessage(programHash, sessionId, msg);
            }
        }
    }

    /**
     * Add tool call message
     */
    public void addToolCallMessage(String toolName, String args, String result) {
        messageStore.addToolCallMessage(toolName, args, result);

        // Save to database
        String programHash = getProgramHash();
        int sessionId = sessionManager.getCurrentSessionId();
        if (programHash != null && sessionId != ChatSessionManager.NO_SESSION) {
            PersistedChatMessage msg = getLastMessage();
            if (msg != null) {
                messageRepository.saveMessage(programHash, sessionId, msg);
            }
        }
    }

    /**
     * Add error message
     */
    public void addError(String errorMessage) {
        messageStore.addErrorMessage(errorMessage);

        // Save to database
        String programHash = getProgramHash();
        int sessionId = sessionManager.getCurrentSessionId();
        if (programHash != null && sessionId != ChatSessionManager.NO_SESSION) {
            PersistedChatMessage msg = getLastMessage();
            if (msg != null) {
                messageRepository.saveMessage(programHash, sessionId, msg);
            }
        }
    }

    // ==================== Conversation Access ====================

    /**
     * Get current conversation history
     */
    public String getConversationHistory() {
        return messageStore.getFormattedConversation();
    }

    /**
     * Clear conversation history
     */
    public void clearConversationHistory() {
        messageStore.clear();
    }

    /**
     * Get the list of persisted messages
     */
    public List<PersistedChatMessage> getMessages() {
        return messageStore.getMessages();
    }

    /**
     * Set the message list (used when loading or after editing)
     */
    public void setMessages(List<PersistedChatMessage> messages) {
        messageStore.setMessages(messages);
    }

    /**
     * Replace all messages in both memory and database.
     * Used for edit operations where the entire conversation is rebuilt.
     *
     * @param messages The new message list
     * @return true if successful
     */
    public boolean replaceAllMessages(List<PersistedChatMessage> messages) {
        String programHash = getProgramHash();
        int sessionId = sessionManager.getCurrentSessionId();

        if (programHash == null || sessionId == ChatSessionManager.NO_SESSION) {
            return false;
        }

        // Update in-memory state
        messageStore.setMessages(messages);

        // Persist to database atomically
        return messageRepository.replaceAllMessages(programHash, sessionId, messages);
    }

    /**
     * Get current provider type
     */
    public String getCurrentProviderType() {
        return messageStore.getCurrentProviderType();
    }

    /**
     * Set current provider type
     */
    public void setCurrentProviderType(String providerType) {
        messageStore.setCurrentProviderType(providerType);
    }

    // ==================== Session Management ====================

    /**
     * Create a new chat session
     */
    public int createNewChatSession() {
        String programHash = getProgramHash();
        if (programHash == null) {
            return -1;
        }
        return sessionManager.createNewSession(programHash);
    }

    /**
     * Get all chat sessions for current program
     */
    public java.util.List<AnalysisDB.ChatSession> getChatSessions() {
        String programHash = getProgramHash();
        if (programHash == null) {
            return new java.util.ArrayList<>();
        }

        // Convert new ChatSession to legacy format for backward compatibility
        List<ChatSession> sessions = sessionManager.getSessions(programHash);
        java.util.List<AnalysisDB.ChatSession> legacySessions = new java.util.ArrayList<>();
        for (ChatSession session : sessions) {
            DocumentChatMetadata metadata = chatHistoryDAO.getDocumentChatMetadata(session.getId());
            legacySessions.add(new AnalysisDB.ChatSession(
                session.getId(),
                session.getDescription(),
                session.getLastUpdate(),
                resolveChatType(metadata)
            ));
        }
        return legacySessions;
    }

    /**
     * Switch to a specific chat session
     */
    public boolean switchToChatSession(int sessionId) {
        String programHash = getProgramHash();
        if (programHash == null) {
            return false;
        }

        // Check if this is a ReAct session (needs special handling)
        if (analysisDB.isReActSession(sessionId)) {
            return switchToReActSession(programHash, sessionId);
        }

        return sessionManager.switchToSession(programHash, sessionId);
    }

    private boolean switchToReActSession(String programHash, int sessionId) {
        java.util.List<ghidrassist.apiprovider.ChatMessage> messages =
            analysisDB.getReActMessages(programHash, sessionId);

        if (messages != null && !messages.isEmpty()) {
            messageStore.clear();

            // Format and set as single message for display
            String formattedConversation = formatReActConversation(messages, sessionId);
            PersistedChatMessage displayMsg = new PersistedChatMessage(
                null, "assistant", formattedConversation,
                new Timestamp(System.currentTimeMillis()), 0
            );
            List<PersistedChatMessage> displayList = new ArrayList<>();
            displayList.add(displayMsg);
            messageStore.setMessages(displayList);

            // Set the session ID so Edit and other operations work
            sessionManager.setCurrentSessionId(sessionId);
            return true;
        }
        return false;
    }

    /**
     * Delete current chat session
     */
    public boolean deleteCurrentSession() {
        return sessionManager.deleteCurrentSession();
    }

    /**
     * Delete a specific chat session by ID
     */
    public boolean deleteSession(int sessionId) {
        return sessionManager.deleteSession(sessionId);
    }

    /**
     * Update chat session description
     */
    public void updateChatDescription(int sessionId, String description) {
        sessionManager.updateSessionDescription(sessionId, description);
    }

    public boolean updateChatType(int sessionId, String chatType) {
        String programHash = getProgramHash();
        if (programHash == null || sessionId == ChatSessionManager.NO_SESSION) {
            return false;
        }

        String normalizedType = normalizeChatType(chatType);
        DocumentChatMetadata metadata = chatHistoryDAO.getDocumentChatMetadata(sessionId);
        metadata.setDocumentChat(isDocumentType(normalizedType));
        metadata.setDocType(normalizedType);
        if (metadata.getSourceSha256() == null) {
            metadata.setSourceSha256(programHash);
        }
        return chatHistoryDAO.upsertDocumentChatMetadata(sessionId, metadata);
    }

    /**
     * Get current session ID
     */
    public int getCurrentSessionId() {
        return sessionManager.getCurrentSessionId();
    }

    /**
     * Ensure session exists
     */
    public void ensureSession() {
        String programHash = getProgramHash();
        if (programHash != null && !messageStore.isEmpty()) {
            sessionManager.ensureSession(programHash);
        }
    }

    // ==================== Document Chat ====================

    /**
     * Set the handler for document chat creation on the native tool manager.
     *
     * @param handler The handler to use for creating document chats
     */
    public void setDocumentChatHandler(DocumentToolProvider.DocumentChatHandler handler) {
        if (nativeToolManager != null) {
            nativeToolManager.setDocumentChatHandler(handler);
        }
    }

    /**
     * Create a detached chat session with document content.
     * The session appears in the sidebar without disrupting the active conversation.
     *
     * @param title   Title for the new chat document
     * @param content Markdown content for the document
     * @return The new session ID, or -1 on failure
     */
    public int createDocumentChat(String title, String content) {
        String programHash = getProgramHash();
        if (programHash == null) {
            return -1;
        }

        int sessionId = sessionManager.createDetachedSession(programHash, title);
        if (sessionId != ChatSessionManager.NO_SESSION) {
            saveDocumentChatContent(programHash, sessionId, title, content, CHAT_TYPE_NOTES, null, 1);
        }
        return sessionId;
    }

    public int upsertSymGraphDocumentChat(Document document) {
        String programHash = getProgramHash();
        if (programHash == null || document == null || document.getDocumentIdentityId() == null) {
            return -1;
        }

        Integer existingSessionId = chatHistoryDAO.findSessionIdByDocumentIdentity(
                programHash, document.getDocumentIdentityId());
        int sessionId;
        if (existingSessionId != null) {
            sessionId = existingSessionId;
            sessionManager.updateSessionDescription(sessionId, document.getTitle());
            saveDocumentChatContent(
                    programHash,
                    sessionId,
                    document.getTitle(),
                    document.getContent(),
                    normalizeDocumentType(document.getDocType()),
                    document.getDocumentIdentityId(),
                    document.getVersion());
        } else {
            sessionId = sessionManager.createDetachedSession(programHash, document.getTitle());
            if (sessionId == ChatSessionManager.NO_SESSION) {
                return -1;
            }
            saveDocumentChatContent(
                    programHash,
                    sessionId,
                    document.getTitle(),
                    document.getContent(),
                    normalizeDocumentType(document.getDocType()),
                    document.getDocumentIdentityId(),
                    document.getVersion());
        }

        return sessionId;
    }

    public List<Map<String, Object>> listDocumentPushCandidates() {
        String programHash = getProgramHash();
        List<Map<String, Object>> candidates = new ArrayList<>();
        if (programHash == null) {
            return candidates;
        }

        for (ChatSession session : sessionManager.getSessions(programHash)) {
            DocumentChatMetadata metadata = chatHistoryDAO.getDocumentChatMetadata(session.getId());
            String chatType = resolveChatType(metadata);
            if (!isDocumentType(chatType)) {
                continue;
            }

            String content = serializeDocumentChat(session.getId());
            if (content == null || content.trim().isEmpty()) {
                continue;
            }

            Map<String, Object> candidate = new HashMap<>();
            candidate.put("session_id", session.getId());
            candidate.put("title", session.getDescription());
            candidate.put("content", content);
            candidate.put("size_bytes", content.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            candidate.put("updated_at", session.getLastUpdate() != null ? session.getLastUpdate().toString() : null);
            candidate.put("version", metadata.getDocumentVersion());
            candidate.put("doc_type", chatType);
            candidate.put("document_identity_id", metadata.getDocumentIdentityId());
            candidates.add(candidate);
        }

        return candidates;
    }

    public boolean updateDocumentSyncMetadata(int sessionId, String documentIdentityId, Integer version, String docType) {
        String programHash = getProgramHash();
        if (programHash == null || sessionId == ChatSessionManager.NO_SESSION) {
            return false;
        }

        DocumentChatMetadata metadata = chatHistoryDAO.getDocumentChatMetadata(sessionId);
        String normalizedType = normalizeDocumentType(docType);
        metadata.setDocumentChat(true);
        metadata.setDocumentIdentityId(documentIdentityId);
        metadata.setDocumentVersion(version);
        metadata.setDocType(normalizedType);
        metadata.setLastSyncedAt(System.currentTimeMillis());
        metadata.setSourceSha256(programHash);
        return chatHistoryDAO.upsertDocumentChatMetadata(sessionId, metadata);
    }

    public String serializeDocumentChat(int sessionId) {
        String programHash = getProgramHash();
        if (programHash == null || sessionId == ChatSessionManager.NO_SESSION) {
            return null;
        }
        return serializeDocumentMessages(messageRepository.loadMessages(programHash, sessionId));
    }

    // ==================== Migration Support ====================

    /**
     * Check if current session has been migrated to per-message storage
     */
    public boolean isMigrated() {
        int sessionId = sessionManager.getCurrentSessionId();
        if (sessionId == ChatSessionManager.NO_SESSION) {
            return false;
        }
        String programHash = getProgramHash();
        return programHash != null && messageRepository.hasMessages(programHash, sessionId);
    }

    /**
     * Migrate legacy conversation blob to per-message storage
     */
    public List<PersistedChatMessage> migrateFromLegacyBlob(String conversation) {
        List<PersistedChatMessage> messages = new ArrayList<>();
        if (conversation == null || conversation.isEmpty()) {
            return messages;
        }

        Pattern pattern = Pattern.compile(
            "\\*\\*(User|Assistant|Error|Tool Call)\\*\\*:\\s*\\n(.*?)(?=\\*\\*(User|Assistant|Error|Tool Call)\\*\\*:|$)",
            Pattern.DOTALL
        );

        Matcher matcher = pattern.matcher(conversation);
        int order = 0;
        while (matcher.find()) {
            String role = RoleNormalizer.normalize(matcher.group(1));
            String content = matcher.group(2).trim();

            PersistedChatMessage msg = new PersistedChatMessage(
                null, role, content,
                new Timestamp(System.currentTimeMillis()),
                order++
            );
            msg.setProviderType("migrated");
            msg.setMessageType("standard");
            msg.setNativeMessageData("{}");
            messages.add(msg);
        }

        return messages;
    }

    /**
     * Load messages from database for current session
     */
    public void loadMessagesFromDatabase() {
        int sessionId = sessionManager.getCurrentSessionId();
        if (sessionId == ChatSessionManager.NO_SESSION) {
            return;
        }
        String programHash = getProgramHash();
        if (programHash == null) {
            return;
        }

        List<PersistedChatMessage> dbMessages = messageRepository.loadMessages(programHash, sessionId);
        if (!dbMessages.isEmpty()) {
            messageStore.setMessages(dbMessages);
        } else {
            // Fall back to legacy blob and migrate
            String conversation = sessionRepository.getLegacyConversation(sessionId);
            if (conversation != null && !conversation.isEmpty()) {
                List<PersistedChatMessage> migrated = migrateFromLegacyBlob(conversation);
                messageStore.setMessages(migrated);

                // Save migrated messages
                for (PersistedChatMessage msg : migrated) {
                    messageRepository.saveMessage(programHash, sessionId, msg);
                }
            }
        }
    }

    // ==================== ReAct Support ====================

    /**
     * Save ReAct analysis to database with full investigation history.
     */
    public void saveReActAnalysis(String userQuery, String investigationHistory, String finalResult) {
        ensureSession();

        int sessionId = sessionManager.getCurrentSessionId();
        if (sessionId == ChatSessionManager.NO_SESSION || plugin.getCurrentProgram() == null) {
            return;
        }

        String programHash = plugin.getCurrentProgram().getExecutableSHA256();

        int existingMessageCount = analysisDB.getReActMessages(programHash, sessionId).size();
        int messageOrder = existingMessageCount;
        int iterationNumber = analysisDB.getMaxReActIteration(programHash, sessionId) + 1;

        // Save user query
        ghidrassist.apiprovider.ChatMessage userMsg =
            new ghidrassist.apiprovider.ChatMessage("user", userQuery);
        analysisDB.saveReActMessage(programHash, sessionId, messageOrder++,
            "planning", null, userMsg);

        // Save investigation history
        if (investigationHistory != null && !investigationHistory.isEmpty()) {
            ghidrassist.apiprovider.ChatMessage investigationMsg =
                new ghidrassist.apiprovider.ChatMessage("assistant", investigationHistory);
            analysisDB.saveReActMessage(programHash, sessionId, messageOrder++,
                "investigation", iterationNumber, investigationMsg);

            analysisDB.saveReActIterationChunk(programHash, sessionId, iterationNumber,
                investigationHistory, messageOrder - 1, messageOrder - 1);
        }

        // Save final synthesis
        ghidrassist.apiprovider.ChatMessage finalMsg =
            new ghidrassist.apiprovider.ChatMessage("assistant", finalResult);
        analysisDB.saveReActMessage(programHash, sessionId, messageOrder++,
            "synthesis", null, finalMsg);
    }

    private String formatReActConversation(java.util.List<ghidrassist.apiprovider.ChatMessage> messages,
                                            int sessionId) {
        StringBuilder conversation = new StringBuilder();
        String userQuery = null;
        String investigationHistory = null;
        String finalSynthesis = null;

        for (ghidrassist.apiprovider.ChatMessage msg : messages) {
            if ("user".equals(msg.getRole())) {
                userQuery = msg.getContent();
            } else if ("assistant".equals(msg.getRole())) {
                if (msg.getContent() != null) {
                    if (investigationHistory == null ||
                        msg.getContent().length() > investigationHistory.length()) {
                        if (investigationHistory != null) {
                            finalSynthesis = investigationHistory;
                        }
                        investigationHistory = msg.getContent();
                    } else {
                        finalSynthesis = msg.getContent();
                    }
                }
            }
        }

        if (userQuery != null) {
            conversation.append("**User**: ").append(userQuery).append("\n\n");
        }
        if (investigationHistory != null) {
            conversation.append(investigationHistory);
            if (finalSynthesis != null && !investigationHistory.contains("# Final")) {
                conversation.append("\n\n---\n\n");
            }
        }
        if (finalSynthesis != null) {
            if (!finalSynthesis.trim().startsWith("#")) {
                conversation.append("# Final Analysis\n\n");
            }
            conversation.append(finalSynthesis).append("\n\n");
        }

        return conversation.toString();
    }

    // ==================== Utility Methods ====================

    private String getProgramHash() {
        if (plugin.getCurrentProgram() != null) {
            return plugin.getCurrentProgram().getExecutableSHA256();
        }
        return null;
    }

    private void saveDocumentChatContent(
            String programHash,
            int sessionId,
            String title,
            String content,
            String docType,
            String documentIdentityId,
            Integer version) {
        PersistedChatMessage msg = new PersistedChatMessage(
                null, "assistant", content != null ? content : "",
                new Timestamp(System.currentTimeMillis()), 0);
        msg.setProviderType("symgraph_document");
        msg.setMessageType("standard");
        List<PersistedChatMessage> messages = new ArrayList<>();
        messages.add(msg);
        messageRepository.replaceAllMessages(programHash, sessionId, messages);
        sessionRepository.touchSession(sessionId);

        String normalizedType = normalizeDocumentType(docType);
        DocumentChatMetadata metadata = chatHistoryDAO.getDocumentChatMetadata(sessionId);
        metadata.setDocumentChat(isDocumentType(normalizedType));
        metadata.setDocumentIdentityId(documentIdentityId);
        metadata.setDocumentVersion(version);
        metadata.setDocType(normalizedType);
        metadata.setLastSyncedAt(System.currentTimeMillis());
        metadata.setSourceSha256(programHash);
        chatHistoryDAO.upsertDocumentChatMetadata(sessionId, metadata);

        if (sessionManager.getCurrentSessionId() == sessionId) {
            messageStore.setMessages(messages);
            sessionManager.updateSessionDescription(sessionId, title);
        }
    }

    private String serializeDocumentMessages(List<PersistedChatMessage> messages) {
        if (messages == null || messages.isEmpty()) {
            return null;
        }
        if (messages.size() == 1) {
            PersistedChatMessage only = messages.get(0);
            if ("assistant".equalsIgnoreCase(only.getRole()) || "edited".equalsIgnoreCase(only.getRole())) {
                return only.getContent();
            }
        }

        StringBuilder markdown = new StringBuilder();
        for (PersistedChatMessage message : messages) {
            if (message == null) {
                continue;
            }
            markdown.append(message.getRoleHeader()).append("\n");
            if (message.getContent() != null) {
                markdown.append(message.getContent());
            }
            markdown.append("\n\n");
        }
        return markdown.toString().trim();
    }

    private String resolveChatType(DocumentChatMetadata metadata) {
        if (metadata == null) {
            return CHAT_TYPE_CHAT;
        }

        String storedType = normalizeStoredChatType(metadata.getDocType());
        if (metadata.isDocumentChat()) {
            return CHAT_TYPE_CHAT.equals(storedType) ? DEFAULT_DOCUMENT_DOC_TYPE : storedType;
        }
        return storedType;
    }

    private String normalizeDocumentType(String docType) {
        String normalized = normalizeStoredChatType(docType);
        return CHAT_TYPE_CHAT.equals(normalized) ? DEFAULT_DOCUMENT_DOC_TYPE : normalized;
    }

    private String normalizeChatType(String chatType) {
        return normalizeStoredChatType(chatType);
    }

    private String normalizeStoredChatType(String chatType) {
        if (chatType == null) {
            return CHAT_TYPE_CHAT;
        }

        String normalized = chatType.trim().toLowerCase();
        return switch (normalized) {
            case "chat" -> CHAT_TYPE_CHAT;
            case "general" -> CHAT_TYPE_GENERAL;
            case "malware report", "malware_report" -> CHAT_TYPE_MALWARE_REPORT;
            case "vulnerability analysis", "vulnerability_analysis", "vuln_analysis" ->
                    CHAT_TYPE_VULNERABILITY_ANALYSIS;
            case "api documentation", "api_documentation", "api_doc", "protocol_spec" ->
                    CHAT_TYPE_API_DOCUMENTATION;
            case "notes" -> CHAT_TYPE_NOTES;
            default -> CHAT_TYPE_CHAT;
        };
    }

    private boolean isDocumentType(String chatType) {
        return !CHAT_TYPE_CHAT.equals(normalizeStoredChatType(chatType));
    }

    private PersistedChatMessage getLastMessage() {
        List<PersistedChatMessage> messages = messageStore.getMessages();
        if (!messages.isEmpty()) {
            return messages.get(messages.size() - 1);
        }
        return null;
    }

    /**
     * Get the AnalysisDB instance (for backward compatibility)
     */
    public AnalysisDB getAnalysisDB() {
        return analysisDB;
    }

    // ==================== Query Request ====================

    /**
     * Request object for query operations
     */
    public static class QueryRequest {
        private final String processedQuery;
        private final String fullConversation;
        private final boolean useMCP;

        public QueryRequest(String processedQuery, String fullConversation, boolean useMCP) {
            this.processedQuery = processedQuery;
            this.fullConversation = fullConversation;
            this.useMCP = useMCP;
        }

        public String getProcessedQuery() { return processedQuery; }
        public String getFullConversation() { return fullConversation; }
        public boolean shouldUseMCP() { return useMCP; }
    }
}
