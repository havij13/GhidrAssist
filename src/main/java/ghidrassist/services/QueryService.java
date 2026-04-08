package ghidrassist.services;

import com.google.gson.JsonObject;
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
import ghidrassist.chat.transcript.TranscriptService;
import ghidrassist.chat.util.RoleNormalizer;
import ghidrassist.context.ContextStatus;
import ghidrassist.context.ContextWindowListener;
import ghidrassist.core.MarkdownHelper;
import ghidrassist.core.QueryProcessor;
import ghidrassist.mcp2.tools.MCPToolManager;
import ghidrassist.tools.native_.DocumentToolProvider;
import ghidrassist.tools.native_.NativeToolManager;
import ghidrassist.tools.approval.ToolApprovalService;
import ghidrassist.tools.approval.ToolRiskTier;
import ghidrassist.tools.registry.ToolRegistry;
import ghidrassist.graphrag.GraphRAGService;
import ghidrassist.services.symgraph.SymGraphModels.Document;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
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
    private final TranscriptService transcriptService;
    private final ToolApprovalService toolApprovalService;
    private final MarkdownHelper markdownHelper;
    private NativeToolManager nativeToolManager;
    private volatile ContextUsageSnapshot contextUsageSnapshot = ContextUsageSnapshot.empty();
    private volatile Consumer<String> contextStatusConsumer;
    private volatile Consumer<PendingApprovalView> pendingApprovalConsumer;
    private volatile Consumer<Integer> transcriptUpdateConsumer;

    public QueryService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.analysisDB = new AnalysisDB();
        this.analysisDataService = new AnalysisDataService(plugin);
        this.markdownHelper = new MarkdownHelper();

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
        this.transcriptService = new TranscriptService(analysisDB.getConnection(), resolveArtifactRoot());
        this.transcriptService.setSessionUpdateListener(this::notifyTranscriptUpdated);
        this.toolApprovalService = new ToolApprovalService(analysisDB.getConnection(), transcriptService);
        this.toolApprovalService.setStateListener(this::notifyPendingApprovalChanged);
        this.toolRegistry.setExecutionObserver(transcriptService);
        this.toolRegistry.setApprovalService(toolApprovalService);
        this.toolRegistry.setActiveSessionSupplier(sessionManager::getCurrentSessionId);
        this.toolRegistry.setProgramHashSupplier(this::getProgramHash);
        resetContextUsage(null, null);
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
        attachContextWindowTracking(llmApi);

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

            if (existingHistory.isEmpty()) {
                llmApi.sendConversationalToolRequest(
                    request.getProcessedQuery(),
                    nativeFunctions,
                    handler,
                    maxToolRounds,
                    toolRegistry
                );
            } else {
                // Use history-aware method to preserve thinking data across turns
                llmApi.sendConversationalToolRequestWithHistory(
                    existingHistory,
                    request.getProcessedQuery(),
                    nativeFunctions,
                    handler,
                    maxToolRounds,
                    toolRegistry
                );
            }
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

            if (existingHistory.isEmpty()) {
                llmApi.sendConversationalToolRequest(
                    request.getProcessedQuery(),
                    allFunctions,
                    handler,
                    maxToolRounds,
                    toolRegistry
                );
            } else {
                // Use history-aware method to preserve thinking data across turns
                llmApi.sendConversationalToolRequestWithHistory(
                    existingHistory,
                    request.getProcessedQuery(),
                    allFunctions,
                    handler,
                    maxToolRounds,
                    toolRegistry
                );
            }
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
                    ghidra.util.Msg.info(this, "Persisting user message to session " + sessionId
                        + " (chars=" + msg.getContent().length() + ")");
                    int messageId = messageRepository.saveMessage(programHash, sessionId, msg);
                    if (messageId > 0) {
                        msg.setDbId(messageId);
                    }
                    transcriptService.appendUserMessage(sessionId, programHash, msg.getContent(), msg.getTimestamp(),
                        msg.getDbId(), msg.getOrder());
                } else {
                    ghidra.util.Msg.warn(this, "User message store was empty after ensuring session " + sessionId);
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
                int messageId = messageRepository.saveMessage(programHash, sessionId, msg);
                if (messageId > 0) {
                    msg.setDbId(messageId);
                }
                transcriptService.appendAssistantMessage(sessionId, programHash, msg.getContent(), msg.getTimestamp(),
                    msg.getDbId(), msg.getOrder());
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
                transcriptService.appendSystemNotice(sessionId, programHash,
                    "Legacy tool message: " + toolName, msg.getContent());
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
                transcriptService.appendSystemNotice(sessionId, programHash, "Error", msg.getContent());
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

    public String getConversationDisplayHtml() {
        int sessionId = sessionManager.getCurrentSessionId();
        if (sessionId == ChatSessionManager.NO_SESSION) {
            return "";
        }
        if (isCurrentSessionEditable()) {
            return markdownHelper.markdownToHtml(getConversationHistory());
        }
        ensureTranscriptForCurrentSession();
        return transcriptService.renderSessionHtml(sessionId);
    }

    public String getConversationPrefixHtml() {
        int sessionId = sessionManager.getCurrentSessionId();
        if (sessionId == ChatSessionManager.NO_SESSION) {
            return "";
        }
        if (isCurrentSessionEditable()) {
            return markdownHelper.markdownToHtmlFragment(getConversationHistory());
        }
        ensureTranscriptForCurrentSession();
        return transcriptService.renderSessionHtmlFragment(sessionId);
    }

    public void setContextStatusConsumer(Consumer<String> contextStatusConsumer) {
        this.contextStatusConsumer = contextStatusConsumer;
    }

    public void setPendingApprovalConsumer(Consumer<PendingApprovalView> pendingApprovalConsumer) {
        this.pendingApprovalConsumer = pendingApprovalConsumer;
    }

    public void setTranscriptUpdateConsumer(Consumer<Integer> transcriptUpdateConsumer) {
        this.transcriptUpdateConsumer = transcriptUpdateConsumer;
    }

    public String getContextStatusText() {
        ContextUsageSnapshot snapshot = contextUsageSnapshot;
        if (snapshot.providerName == null || snapshot.providerName.isBlank()
                || snapshot.modelName == null || snapshot.modelName.isBlank()) {
            ProviderIdentity identity = resolveCurrentProviderIdentity();
            snapshot = snapshot.withProvider(identity.providerName(), identity.modelName());
        }
        return snapshot.toDisplayString();
    }

    public PendingApprovalView getCurrentPendingApprovalView() {
        ToolApprovalService.PendingApproval pending =
            toolApprovalService.getFirstPendingApprovalForSession(sessionManager.getCurrentSessionId());
        if (pending == null) {
            return null;
        }
        String argsPreview = pending.getArgs() != null ? pending.getArgs().toString() : "{}";
        return new PendingApprovalView(
            pending.getRequestId(),
            pending.getToolName(),
            pending.getToolSource(),
            pending.getRiskTier(),
            argsPreview
        );
    }

    public boolean resolvePendingApproval(String requestId, String decision) {
        return toolApprovalService.resolvePendingApproval(requestId, decision);
    }

    /**
     * Clear conversation history
     */
    public void clearConversationHistory() {
        toolApprovalService.cancelPendingApprovalsForSession(sessionManager.getCurrentSessionId(), "session cleared");
        messageStore.clear();
        resetContextUsage(null, null);
        notifyPendingApprovalChanged();
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
        resetContextUsage(null, null);
        notifyPendingApprovalChanged();
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

        boolean switched = sessionManager.switchToSession(programHash, sessionId);
        if (switched) {
            transcriptService.ensureBackfilledFromMessages(programHash, sessionId, messageStore.getMessages());
            resetContextUsage(null, null);
            notifyPendingApprovalChanged();
        }
        return switched;
    }

    private boolean switchToReActSession(String programHash, int sessionId) {
        java.util.List<ghidrassist.apiprovider.ChatMessage> messages =
            analysisDB.getReActMessages(programHash, sessionId);

        if (messages != null && !messages.isEmpty()) {
            messageStore.clear();
            transcriptService.ensureBackfilledFromReActMessages(programHash, sessionId, messages);

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
            resetContextUsage(null, null);
            notifyPendingApprovalChanged();
            return true;
        }
        return false;
    }

    public boolean isCurrentSessionEditable() {
        return isSessionEditable(sessionManager.getCurrentSessionId());
    }

    /**
     * Delete current chat session
     */
    public boolean deleteCurrentSession() {
        toolApprovalService.cancelPendingApprovalsForSession(sessionManager.getCurrentSessionId(), "session deleted");
        resetContextUsage(null, null);
        notifyPendingApprovalChanged();
        return sessionManager.deleteCurrentSession();
    }

    /**
     * Delete a specific chat session by ID
     */
    public boolean deleteSession(int sessionId) {
        if (sessionId == sessionManager.getCurrentSessionId()) {
            toolApprovalService.cancelPendingApprovalsForSession(sessionId, "session deleted");
            resetContextUsage(null, null);
            notifyPendingApprovalChanged();
        }
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
            transcriptService.ensureBackfilledFromMessages(programHash, sessionId, dbMessages);
        } else {
            // Fall back to legacy blob and migrate
            String conversation = sessionRepository.getLegacyConversation(sessionId);
            if (conversation != null && !conversation.isEmpty()) {
                List<PersistedChatMessage> migrated = migrateFromLegacyBlob(conversation);
                messageStore.setMessages(migrated);
                transcriptService.ensureBackfilledFromMessages(programHash, sessionId, migrated);

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
        transcriptService.appendUserMessage(sessionId, programHash, userQuery,
            new Timestamp(System.currentTimeMillis()));

        // Save investigation history
        if (investigationHistory != null && !investigationHistory.isEmpty()) {
            ghidrassist.apiprovider.ChatMessage investigationMsg =
                new ghidrassist.apiprovider.ChatMessage("assistant", investigationHistory);
            analysisDB.saveReActMessage(programHash, sessionId, messageOrder++,
                "investigation", iterationNumber, investigationMsg);
            transcriptService.appendAssistantMessage(sessionId, programHash, investigationHistory,
                new Timestamp(System.currentTimeMillis()));

            analysisDB.saveReActIterationChunk(programHash, sessionId, iterationNumber,
                investigationHistory, messageOrder - 1, messageOrder - 1);
        }

        // Save final synthesis
        ghidrassist.apiprovider.ChatMessage finalMsg =
            new ghidrassist.apiprovider.ChatMessage("assistant", finalResult);
        analysisDB.saveReActMessage(programHash, sessionId, messageOrder++,
            "synthesis", null, finalMsg);
        transcriptService.appendAssistantMessage(sessionId, programHash, finalResult,
            new Timestamp(System.currentTimeMillis()));
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
        transcriptService.appendDocumentSnapshot(sessionId, programHash, title, content != null ? content : "");

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

    private boolean isSessionEditable(int sessionId) {
        if (sessionId == ChatSessionManager.NO_SESSION || analysisDB.isReActSession(sessionId)) {
            return false;
        }
        DocumentChatMetadata metadata = chatHistoryDAO.getDocumentChatMetadata(sessionId);
        return isDocumentType(resolveChatType(metadata));
    }

    private void ensureTranscriptForCurrentSession() {
        int sessionId = sessionManager.getCurrentSessionId();
        String programHash = getProgramHash();
        if (sessionId == ChatSessionManager.NO_SESSION || programHash == null) {
            return;
        }
        if (analysisDB.isReActSession(sessionId)) {
            transcriptService.ensureBackfilledFromReActMessages(programHash, sessionId,
                analysisDB.getReActMessages(programHash, sessionId));
        } else {
            transcriptService.ensureBackfilledFromMessages(programHash, sessionId, messageStore.getMessages());
        }
    }

    private Path resolveArtifactRoot() {
        String databasePath = analysisDB.getDatabasePath();
        if (databasePath == null || databasePath.isBlank()) {
            return Paths.get("ghidrassist_chat_artifacts").toAbsolutePath();
        }
        Path dbPath = Paths.get(databasePath).toAbsolutePath();
        Path parent = dbPath.getParent();
        if (parent == null) {
            parent = Paths.get(".").toAbsolutePath();
        }
        return parent.resolve("ghidrassist_chat_artifacts");
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

    public TranscriptService getTranscriptService() {
        return transcriptService;
    }

    public void toggleToolGroupExpansion(String correlationId) {
        transcriptService.toggleToolGroupExpansion(correlationId);
    }

    public ToolApprovalService getToolApprovalService() {
        return toolApprovalService;
    }

    public void attachContextWindowTracking(LlmApi llmApi) {
        if (llmApi == null) {
            resetContextUsage(null, null);
            return;
        }
        String providerName = llmApi.getProviderName();
        String modelName = llmApi.getProviderModel();
        resetContextUsage(providerName, modelName);
        llmApi.setContextWindowListener(createContextWindowListener(providerName, modelName));
    }

    public void beginContextTracking(String providerName, String modelName) {
        resetContextUsage(providerName, modelName);
    }

    public ContextWindowListener createContextWindowListener(String providerName, String modelName) {
        return new ContextWindowListener() {
            @Override
            public void onStatusUpdated(ContextStatus status) {
                contextUsageSnapshot = ContextUsageSnapshot.fromStatus(providerName, modelName, status,
                    contextUsageSnapshot.compacted);
                notifyContextStatusChanged();
            }

            @Override
            public void onContextCompacted(String summary, int originalMessageCount, int finalMessageCount) {
                contextUsageSnapshot = contextUsageSnapshot.withCompacted(summary, finalMessageCount);
                int sessionId = sessionManager.getCurrentSessionId();
                String programHash = getProgramHash();
                if (sessionId != ChatSessionManager.NO_SESSION && programHash != null) {
                    JsonObject metadata = new JsonObject();
                    metadata.addProperty("provider", providerName);
                    metadata.addProperty("model", modelName);
                    metadata.addProperty("original_message_count", originalMessageCount);
                    metadata.addProperty("final_message_count", finalMessageCount);
                    if (contextUsageSnapshot.currentTokens != null) {
                        metadata.addProperty("current_tokens", contextUsageSnapshot.currentTokens);
                    }
                    if (contextUsageSnapshot.maxTokens != null) {
                        metadata.addProperty("max_tokens", contextUsageSnapshot.maxTokens);
                    }
                    if (contextUsageSnapshot.thresholdTokens != null) {
                        metadata.addProperty("threshold_tokens", contextUsageSnapshot.thresholdTokens);
                    }
                    transcriptService.appendContextCompacted(sessionId, programHash, summary, metadata.toString());
                }
                notifyContextStatusChanged();
            }
        };
    }

    private void resetContextUsage(String providerName, String modelName) {
        ProviderIdentity identity = resolveCurrentProviderIdentity();
        String resolvedProvider = firstNonBlank(providerName, identity.providerName());
        String resolvedModel = firstNonBlank(modelName, identity.modelName());
        contextUsageSnapshot = ContextUsageSnapshot.empty(resolvedProvider, resolvedModel);
        notifyContextStatusChanged();
    }

    private ProviderIdentity resolveCurrentProviderIdentity() {
        try {
            APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
            if (config == null) {
                return ProviderIdentity.EMPTY;
            }
            return new ProviderIdentity(
                firstNonBlank(config.getName(), "No provider"),
                firstNonBlank(config.getModel(), "No model")
            );
        } catch (Exception e) {
            ghidra.util.Msg.debug(this, "Unable to resolve current provider identity: " + e.getMessage());
            return ProviderIdentity.EMPTY;
        }
    }

    private String firstNonBlank(String primary, String fallback) {
        return primary != null && !primary.isBlank() ? primary : fallback;
    }

    private void notifyContextStatusChanged() {
        Consumer<String> consumer = contextStatusConsumer;
        if (consumer != null) {
            consumer.accept(getContextStatusText());
        }
    }

    private void notifyPendingApprovalChanged() {
        Consumer<PendingApprovalView> consumer = pendingApprovalConsumer;
        if (consumer != null) {
            consumer.accept(getCurrentPendingApprovalView());
        }
    }

    private void notifyTranscriptUpdated(int sessionId) {
        Consumer<Integer> consumer = transcriptUpdateConsumer;
        if (consumer != null) {
            consumer.accept(sessionId);
        }
    }

    private static class ContextUsageSnapshot {
        private final String providerName;
        private final String modelName;
        private final Integer currentTokens;
        private final Integer maxTokens;
        private final Integer messageCount;
        private final Integer thresholdTokens;
        private final boolean compacted;
        private final String note;

        private ContextUsageSnapshot(String providerName, String modelName, Integer currentTokens,
                                     Integer maxTokens, Integer messageCount, Integer thresholdTokens,
                                     boolean compacted, String note) {
            this.providerName = providerName;
            this.modelName = modelName;
            this.currentTokens = currentTokens;
            this.maxTokens = maxTokens;
            this.messageCount = messageCount;
            this.thresholdTokens = thresholdTokens;
            this.compacted = compacted;
            this.note = note;
        }

        private static ContextUsageSnapshot empty() {
            return empty(null, null);
        }

        private static ContextUsageSnapshot empty(String providerName, String modelName) {
            return new ContextUsageSnapshot(providerName, modelName, null, null, null, null,
                false, "No active context window data");
        }

        private static ContextUsageSnapshot fromStatus(String providerName, String modelName,
                                                       ContextStatus status, boolean compacted) {
            return new ContextUsageSnapshot(
                providerName,
                modelName,
                status != null ? status.getCurrentTokens() : null,
                status != null ? status.getMaxTokens() : null,
                status != null ? status.getMessageCount() : null,
                status != null ? status.getCompressionThresholdTokens() : null,
                compacted,
                status != null ? status.getStatusMessage() : "No active context window data"
            );
        }

        private ContextUsageSnapshot withCompacted(String note, Integer finalMessageCount) {
            return new ContextUsageSnapshot(
                providerName,
                modelName,
                currentTokens,
                maxTokens,
                finalMessageCount != null ? finalMessageCount : messageCount,
                thresholdTokens,
                true,
                note
            );
        }

        private ContextUsageSnapshot withProvider(String providerName, String modelName) {
            return new ContextUsageSnapshot(
                providerName != null && !providerName.isBlank() ? providerName : this.providerName,
                modelName != null && !modelName.isBlank() ? modelName : this.modelName,
                currentTokens,
                maxTokens,
                messageCount,
                thresholdTokens,
                compacted,
                note
            );
        }

        private String toDisplayString() {
            String provider = providerName != null && !providerName.isBlank() ? providerName : "No provider";
            String model = modelName != null && !modelName.isBlank() ? modelName : "No model";
            if (currentTokens == null || maxTokens == null) {
                return String.format("Model: %s / %s | %s", provider, model, note);
            }
            String compactedLabel = compacted ? " | compacted" : "";
            String messageLabel = messageCount != null ? " | " + messageCount + " msgs" : "";
            String thresholdLabel = thresholdTokens != null ? " | threshold " + thresholdTokens : "";
            return String.format(
                "Model: %s / %s | context %d/%d tokens%s%s%s",
                provider,
                model,
                currentTokens,
                maxTokens,
                messageLabel,
                thresholdLabel,
                compactedLabel
            );
        }
    }

    private record ProviderIdentity(String providerName, String modelName) {
        private static final ProviderIdentity EMPTY = new ProviderIdentity(null, null);
    }

    public static class PendingApprovalView {
        private final String requestId;
        private final String toolName;
        private final String toolSource;
        private final ToolRiskTier riskTier;
        private final String argsPreview;

        public PendingApprovalView(String requestId, String toolName, String toolSource,
                                   ToolRiskTier riskTier, String argsPreview) {
            this.requestId = requestId;
            this.toolName = toolName;
            this.toolSource = toolSource;
            this.riskTier = riskTier;
            this.argsPreview = argsPreview;
        }

        public String getRequestId() {
            return requestId;
        }

        public String getToolName() {
            return toolName;
        }

        public String getToolSource() {
            return toolSource;
        }

        public ToolRiskTier getRiskTier() {
            return riskTier;
        }

        public String getArgsPreview() {
            return argsPreview;
        }
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
