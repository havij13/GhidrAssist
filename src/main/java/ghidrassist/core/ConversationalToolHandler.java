package ghidrassist.core;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.AnthropicPlatformApiProvider;
import ghidrassist.apiprovider.OpenAIPlatformApiProvider;
import ghidrassist.apiprovider.LMStudioProvider;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.exceptions.RateLimitException;
import ghidrassist.tools.api.ToolResult;
import ghidrassist.tools.registry.ToolRegistry;
import ghidra.util.Msg;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Handles conversational tool calling with proper finish_reason monitoring.
 * Manages the turn-by-turn conversation flow with the LLM and MCP tool execution.
 */
public class ConversationalToolHandler {

    private final LlmApiClient apiClient;
    private final List<Map<String, Object>> availableFunctions;
    private final ResponseProcessor responseProcessor;
    private final LlmApi.LlmResponseHandler userHandler;
    @SuppressWarnings("unused")  // Reserved for future error handling enhancement
    private final LlmErrorHandler errorHandler;
    private final Runnable onCompletionCallback;
    private final ToolRegistry toolRegistry;

    private final List<ChatMessage> conversationHistory;
    private volatile boolean isConversationActive = false;
    private volatile boolean isCancelled = false;
    private int rateLimitRetries = 0;
    private int toolCallRound = 0; // Track tool calling rounds within iteration
    private static final int MAX_RATE_LIMIT_BACKOFF_SECONDS = 60;
    private static final int MAX_CONVERSATION_HISTORY = 20; // Keep last 20 messages to prevent token overflow
    private final int maxToolRounds; // Maximum tool calling rounds per iteration (configurable)
    private static final int API_TIMEOUT_SECONDS = 300; // Timeout for blocking API calls (generous for rate limit retries)

    public ConversationalToolHandler(
            LlmApiClient apiClient,
            List<Map<String, Object>> functions,
            ResponseProcessor responseProcessor,
            LlmApi.LlmResponseHandler userHandler,
            LlmErrorHandler errorHandler,
            Runnable onCompletionCallback,
            int maxToolRounds,
            ToolRegistry toolRegistry) {

        this.apiClient = apiClient;
        this.availableFunctions = functions;
        this.responseProcessor = responseProcessor;
        this.userHandler = userHandler;
        this.errorHandler = errorHandler;
        this.onCompletionCallback = onCompletionCallback;
        this.conversationHistory = new ArrayList<>();
        this.maxToolRounds = maxToolRounds > 0 ? maxToolRounds : 10; // Default to 10 if invalid
        this.toolRegistry = toolRegistry;
    }
    
    /**
     * Start the conversational tool calling session
     */
    public void startConversation(String userPrompt) {
        if (isConversationActive) {
            Msg.warn(this, "Conversation already active, ignoring new request");
            return;
        }

        // Validate prompt is not empty - this can happen on first load with stale state
        if (userPrompt == null || userPrompt.trim().isEmpty()) {
            Msg.warn(this, "Empty prompt received, cannot start conversation");
            userHandler.onError(new IllegalArgumentException(
                "Cannot process empty query. Please try again."));
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
            return;
        }

        isConversationActive = true;
        isCancelled = false; // Reset cancellation flag
        conversationHistory.clear();
        rateLimitRetries = 0; // Reset retry counter
        toolCallRound = 0; // Reset tool call round counter

        // Add initial user message
        conversationHistory.addAll(apiClient.createFunctionMessages(userPrompt));
        
        // Start the conversation loop
        userHandler.onStart();

        // Provide user feedback about automatic rate limit handling
        userHandler.onUpdate("🔄 Starting conversational tool calling (automatic retry on rate limits)...\n\n");

        continueConversation();
    }

    /**
     * Start the conversational tool calling session with existing history.
     * This preserves thinking content, tool calls, and other metadata from previous turns.
     *
     * @param existingHistory List of ChatMessages from previous conversation (with thinking data)
     * @param newUserPrompt The new user message to add
     */
    public void startConversationWithHistory(List<ChatMessage> existingHistory, String newUserPrompt) {
        if (isConversationActive) {
            Msg.warn(this, "Conversation already active, ignoring new request");
            return;
        }

        // Validate prompt is not empty
        if (newUserPrompt == null || newUserPrompt.trim().isEmpty()) {
            Msg.warn(this, "Empty prompt received, cannot start conversation");
            userHandler.onError(new IllegalArgumentException(
                "Cannot process empty query. Please try again."));
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
            return;
        }

        isConversationActive = true;
        isCancelled = false;
        conversationHistory.clear();
        rateLimitRetries = 0;
        toolCallRound = 0;

        // Add system message first
        conversationHistory.add(new ChatMessage(
            ChatMessage.ChatMessageRole.SYSTEM,
            apiClient.getCurrentContext()
        ));

        // Add existing history (preserving thinking data, tool calls, etc.)
        // Skip any system messages in the history since we just added our own
        if (existingHistory != null) {
            for (ChatMessage msg : existingHistory) {
                if (!ChatMessage.ChatMessageRole.SYSTEM.equals(msg.getRole())) {
                    conversationHistory.add(msg);
                }
            }
        }

        // Add new user message
        conversationHistory.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, newUserPrompt));

        // Start the conversation loop
        userHandler.onStart();
        userHandler.onUpdate("🔄 Continuing conversation with history...\n\n");

        // Validate imported history before starting - existing history may have orphaned tool_calls
        validateAndRepairConversationHistory();

        continueConversation();
    }

    /**
     * Cancel the ongoing conversation
     */
    public void cancel() {
        isCancelled = true;
        isConversationActive = false;

        // Clean up any orphaned tool_calls in history from in-progress tool execution.
        // Tool execution may still be running on another thread; the flush in
        // executeToolsSequentially will also add results, but validate/repair catches
        // any remaining gaps.
        validateAndRepairConversationHistory();

        userHandler.onUpdate("\n❌ **Cancelled**\n");
        userHandler.onComplete("Conversation cancelled");

        // Notify completion callback
        if (onCompletionCallback != null) {
            onCompletionCallback.run();
        }
    }
    
    /**
     * Continue the conversation with the current message history.
     * Supports multi-turn tool calling with safety limit (max 10 rounds per iteration).
     */
    private void continueConversation() {
        if (!isConversationActive || isCancelled) {
            return;
        }

        // Check tool calling round limit (safety mechanism for infinite loops)
        if (toolCallRound >= maxToolRounds) {
            Msg.warn(this, String.format(
                "Reached maximum tool calling rounds (%d). Completing conversation to prevent infinite loops.",
                maxToolRounds
            ));
            userHandler.onUpdate(String.format(
                "\n⚠️ **Maximum tool rounds reached (%d)** - Completing investigation with current findings.\n\n",
                maxToolRounds
            ));
            isConversationActive = false;
            userHandler.onComplete("Maximum tool calling rounds reached");
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
            return;
        }

        try {
            // Trim conversation history to prevent token overflow
            trimConversationHistory();

            // Validate and repair any orphaned tool_calls before sending to API
            validateAndRepairConversationHistory();

            // Log conversation structure for debugging
            logConversationStructure();

            // Call LLM with current conversation history
            // Use streaming if provider supports it (Anthropic, OpenAI, LMStudio), otherwise blocking
            if (apiClient.getProvider() instanceof AnthropicPlatformApiProvider ||
                apiClient.getProvider() instanceof OpenAIPlatformApiProvider ||
                apiClient.getProvider() instanceof LMStudioProvider) {
                streamingConversationWithFunctions();
            } else {
                // Non-streaming providers (OpenWebUI, Ollama, etc.) - use timeout protection
                CompletableFuture<String> apiFuture = CompletableFuture.supplyAsync(() -> {
                    try {
                        // Check cancellation before making API call
                        if (isCancelled) {
                            return null;
                        }

                        return apiClient.createChatCompletionWithFunctionsFullResponse(
                            conversationHistory, availableFunctions);

                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });

                // Apply timeout to prevent indefinite hangs
                apiFuture
                    .orTimeout(API_TIMEOUT_SECONDS, java.util.concurrent.TimeUnit.SECONDS)
                    .thenAccept(fullResponse -> {
                        // Check cancellation after API call
                        if (isCancelled || fullResponse == null) {
                            return;
                        }

                        // Parse the response to check for tool calls and finish_reason
                        handleLLMResponse(fullResponse);
                    })
                    .exceptionally(e -> {
                        Throwable cause = e.getCause() != null ? e.getCause() : e;

                        // Handle timeout specifically
                        if (e instanceof java.util.concurrent.TimeoutException ||
                            cause instanceof java.util.concurrent.TimeoutException) {
                            Msg.warn(this, "API call timed out after " + API_TIMEOUT_SECONDS + " seconds");
                            isConversationActive = false;
                            userHandler.onUpdate("❌ **Request timed out** - The model stopped responding. Please try again.\n");
                            userHandler.onError(new Exception("API request timed out after " + API_TIMEOUT_SECONDS + " seconds. The model may be overloaded."));

                            if (onCompletionCallback != null) {
                                onCompletionCallback.run();
                            }
                            return null;
                        }

                        // Handle rate limit errors - always retry, never give up
                        String errorMsg = cause.getMessage() != null ? cause.getMessage() : "";
                        if (cause instanceof ghidrassist.apiprovider.exceptions.RateLimitException ||
                            errorMsg.contains("rate limit") ||
                            errorMsg.contains("429")) {

                            rateLimitRetries++;
                            Msg.warn(this, String.format("Rate limit exceeded during conversational tool calling (attempt %d). Retrying with backoff...",
                                rateLimitRetries));

                            // Backoff: 10s, 20s, 30s, ... capped at MAX_RATE_LIMIT_BACKOFF_SECONDS
                            int backoffSeconds = Math.min(10 * rateLimitRetries, MAX_RATE_LIMIT_BACKOFF_SECONDS);
                            userHandler.onUpdate(String.format("⏳ Rate limit hit. Pausing for %d seconds...\n",
                                backoffSeconds));

                            CompletableFuture.delayedExecutor(backoffSeconds, java.util.concurrent.TimeUnit.SECONDS)
                                .execute(() -> {
                                    if (isConversationActive && !isCancelled) {
                                        userHandler.onUpdate("🔄 Resuming...\n");
                                        continueConversation();
                                    }
                                });
                        } else {
                            // Non-rate-limit errors stop the conversation
                            isConversationActive = false;
                            userHandler.onError(cause instanceof Exception ? (Exception) cause : new Exception(cause));

                            if (onCompletionCallback != null) {
                                onCompletionCallback.run();
                            }
                        }
                        return null;
                    });
            }

        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Stream conversation with functions using provider's streaming API.
     * Supports Anthropic, OpenAI, and LMStudio providers.
     * Text content streams immediately; tool calls execute after streaming completes.
     */
    private void streamingConversationWithFunctions() {
        try {
            if (apiClient.getProvider() instanceof AnthropicPlatformApiProvider) {
                streamWithAnthropicPlatformApiProvider();
            } else if (apiClient.getProvider() instanceof OpenAIPlatformApiProvider) {
                streamWithOpenAIPlatformApiProvider();
            } else if (apiClient.getProvider() instanceof LMStudioProvider) {
                streamWithLMStudioProvider();
            }
        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Stream conversation using Anthropic provider.
     */
    private void streamWithAnthropicPlatformApiProvider() {
        try {
            AnthropicPlatformApiProvider provider = (AnthropicPlatformApiProvider) apiClient.getProvider();

            provider.streamChatCompletionWithFunctions(
                conversationHistory,
                availableFunctions,
                new AnthropicPlatformApiProvider.StreamingFunctionHandler() {
                    @Override
                    public void onTextUpdate(String textDelta) {
                        // Stream text to UI immediately
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            if (!isCancelled) {
                                userHandler.onUpdate(textDelta);
                            }
                        });
                    }

                    @Override
                    public void onStreamComplete(String stopReason, String fullText, String thinkingContent, String thinkingSignature, List<AnthropicPlatformApiProvider.ToolCall> toolCalls) {
                        // Create assistant message with text content
                        ChatMessage assistantMsg = new ChatMessage(ChatMessage.ChatMessageRole.ASSISTANT, fullText);

                        // Store thinking content and signature if present
                        if (thinkingContent != null && !thinkingContent.isEmpty()) {
                            assistantMsg.setThinkingContent(thinkingContent);
                        }
                        if (thinkingSignature != null && !thinkingSignature.isEmpty()) {
                            assistantMsg.setThinkingSignature(thinkingSignature);
                        }

                        // Only attach tool calls when stopReason indicates tool use.
                        // If stopReason is "stop" but streaming accumulated partial tool call deltas,
                        // attaching them creates orphaned tool_calls (no results will follow).
                        if ("tool_use".equals(stopReason) && !toolCalls.isEmpty()) {
                            JsonArray toolCallsArray = new JsonArray();
                            for (AnthropicPlatformApiProvider.ToolCall toolCall : toolCalls) {
                                JsonObject toolCallObj = new JsonObject();
                                toolCallObj.addProperty("id", toolCall.id);
                                toolCallObj.addProperty("type", "function");

                                JsonObject function = new JsonObject();
                                function.addProperty("name", toolCall.name);
                                function.addProperty("arguments", toolCall.arguments);
                                toolCallObj.add("function", function);

                                toolCallsArray.add(toolCallObj);
                            }

                            // Attach tool calls to assistant message
                            assistantMsg.setToolCalls(toolCallsArray);
                        } else if (!toolCalls.isEmpty()) {
                            Msg.warn(ConversationalToolHandler.this,
                                String.format("Discarding %d tool calls because stopReason='%s' (expected 'tool_use')",
                                    toolCalls.size(), stopReason));
                        }

                        // Add assistant message to conversation history
                        conversationHistory.add(assistantMsg);

                        if ("tool_use".equals(stopReason) && !toolCalls.isEmpty()) {
                            // Increment tool call round counter (multi-turn tracking)
                            toolCallRound++;
                            Msg.debug(ConversationalToolHandler.this,
                                String.format("Tool calling round %d/%d", toolCallRound, maxToolRounds));

                            // Execute tools after text streaming completes
                            handleToolCallsFromStream(toolCalls);
                        } else {
                            // Conversation complete - pass the full response text
                            handleConversationEndFromStream(fullText);
                        }
                    }

                    @Override
                    public void onError(Throwable error) {
                        // Handle rate limit errors - always retry, never give up
                        if (error instanceof RateLimitException ||
                            error.getMessage().contains("rate limit") ||
                            error.getMessage().contains("429")) {

                            rateLimitRetries++;
                            Msg.warn(ConversationalToolHandler.this,
                                String.format("Rate limit exceeded during streaming (attempt %d). Retrying with backoff...",
                                    rateLimitRetries));

                            int backoffSeconds = Math.min(10 * rateLimitRetries, MAX_RATE_LIMIT_BACKOFF_SECONDS);
                            userHandler.onUpdate(String.format("⏳ Rate limit hit. Pausing for %d seconds...\n",
                                backoffSeconds));

                            CompletableFuture.delayedExecutor(backoffSeconds, java.util.concurrent.TimeUnit.SECONDS)
                                .execute(() -> {
                                    if (isConversationActive && !isCancelled) {
                                        userHandler.onUpdate("🔄 Resuming...\n");
                                        continueConversation();
                                    }
                                });
                        } else {
                            // Non-rate-limit errors stop the conversation
                            isConversationActive = false;
                            userHandler.onError(error);

                            if (onCompletionCallback != null) {
                                onCompletionCallback.run();
                            }
                        }
                    }

                    @Override
                    public boolean shouldContinue() {
                        return !isCancelled && isConversationActive;
                    }
                }
            );

        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Stream conversation using OpenAI provider.
     */
    private void streamWithOpenAIPlatformApiProvider() {
        try {
            OpenAIPlatformApiProvider provider = (OpenAIPlatformApiProvider) apiClient.getProvider();

            provider.streamChatCompletionWithFunctions(
                conversationHistory,
                availableFunctions,
                new OpenAIPlatformApiProvider.StreamingFunctionHandler() {
                    @Override
                    public void onTextUpdate(String textDelta) {
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            if (!isCancelled) {
                                userHandler.onUpdate(textDelta);
                            }
                        });
                    }

                    @Override
                    public void onStreamComplete(String stopReason, String fullText, List<OpenAIPlatformApiProvider.ToolCall> toolCalls) {
                        ChatMessage assistantMsg = new ChatMessage(ChatMessage.ChatMessageRole.ASSISTANT, fullText);

                        // Only attach tool calls when stopReason indicates tool calling.
                        // If stopReason is "stop" but streaming accumulated partial tool call deltas,
                        // attaching them creates orphaned tool_calls (no results will follow).
                        if ("tool_calls".equals(stopReason) && !toolCalls.isEmpty()) {
                            JsonArray toolCallsArray = new JsonArray();
                            for (OpenAIPlatformApiProvider.ToolCall toolCall : toolCalls) {
                                JsonObject toolCallObj = new JsonObject();
                                toolCallObj.addProperty("id", toolCall.id);
                                toolCallObj.addProperty("type", "function");

                                JsonObject function = new JsonObject();
                                function.addProperty("name", toolCall.name);
                                function.addProperty("arguments", toolCall.arguments);
                                toolCallObj.add("function", function);

                                toolCallsArray.add(toolCallObj);
                            }
                            assistantMsg.setToolCalls(toolCallsArray);
                        } else if (!toolCalls.isEmpty()) {
                            Msg.warn(ConversationalToolHandler.this,
                                String.format("Discarding %d tool calls because stopReason='%s' (expected 'tool_calls')",
                                    toolCalls.size(), stopReason));
                        }

                        conversationHistory.add(assistantMsg);

                        if ("tool_calls".equals(stopReason) && !toolCalls.isEmpty()) {
                            // Increment tool call round counter (multi-turn tracking)
                            toolCallRound++;
                            Msg.debug(ConversationalToolHandler.this,
                                String.format("Tool calling round %d/%d", toolCallRound, maxToolRounds));

                            handleToolCallsFromOpenAIStream(toolCalls);
                        } else {
                            // Conversation complete - pass the full response text
                            handleConversationEndFromStream(fullText);
                        }
                    }

                    @Override
                    public void onError(Throwable error) {
                        handleStreamingError(error);
                    }

                    @Override
                    public boolean shouldContinue() {
                        return !isCancelled && isConversationActive;
                    }
                }
            );

        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Stream conversation using LMStudio provider.
     */
    private void streamWithLMStudioProvider() {
        try {
            LMStudioProvider provider = (LMStudioProvider) apiClient.getProvider();

            provider.streamChatCompletionWithFunctions(
                conversationHistory,
                availableFunctions,
                new LMStudioProvider.StreamingFunctionHandler() {
                    @Override
                    public void onTextUpdate(String textDelta) {
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            if (!isCancelled) {
                                userHandler.onUpdate(textDelta);
                            }
                        });
                    }

                    @Override
                    public void onStreamComplete(String stopReason, String fullText, List<LMStudioProvider.ToolCall> toolCalls) {
                        ChatMessage assistantMsg = new ChatMessage(ChatMessage.ChatMessageRole.ASSISTANT, fullText);

                        // Only attach tool calls when stopReason indicates tool calling.
                        // If stopReason is "stop" but streaming accumulated partial tool call deltas,
                        // attaching them creates orphaned tool_calls (no results will follow).
                        if ("tool_calls".equals(stopReason) && !toolCalls.isEmpty()) {
                            JsonArray toolCallsArray = new JsonArray();
                            for (LMStudioProvider.ToolCall toolCall : toolCalls) {
                                JsonObject toolCallObj = new JsonObject();
                                toolCallObj.addProperty("id", toolCall.id);
                                toolCallObj.addProperty("type", "function");

                                JsonObject function = new JsonObject();
                                function.addProperty("name", toolCall.name);
                                function.addProperty("arguments", toolCall.arguments);
                                toolCallObj.add("function", function);

                                toolCallsArray.add(toolCallObj);
                            }
                            assistantMsg.setToolCalls(toolCallsArray);
                        } else if (!toolCalls.isEmpty()) {
                            Msg.warn(ConversationalToolHandler.this,
                                String.format("Discarding %d tool calls because stopReason='%s' (expected 'tool_calls')",
                                    toolCalls.size(), stopReason));
                        }

                        conversationHistory.add(assistantMsg);

                        if ("tool_calls".equals(stopReason) && !toolCalls.isEmpty()) {
                            // Increment tool call round counter (multi-turn tracking)
                            toolCallRound++;
                            Msg.debug(ConversationalToolHandler.this,
                                String.format("Tool calling round %d/%d", toolCallRound, maxToolRounds));

                            handleToolCallsFromLMStudioStream(toolCalls);
                        } else {
                            // Conversation complete - pass the full response text
                            handleConversationEndFromStream(fullText);
                        }
                    }

                    @Override
                    public void onError(Throwable error) {
                        handleStreamingError(error);
                    }

                    @Override
                    public boolean shouldContinue() {
                        return !isCancelled && isConversationActive;
                    }
                }
            );

        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Common error handling for streaming providers.
     */
    private void handleStreamingError(Throwable error) {
        if (error instanceof RateLimitException ||
            error.getMessage().contains("rate limit") ||
            error.getMessage().contains("429")) {

            rateLimitRetries++;
            Msg.warn(ConversationalToolHandler.this,
                String.format("Rate limit exceeded during streaming (attempt %d). Retrying with backoff...",
                    rateLimitRetries));

            int backoffSeconds = Math.min(10 * rateLimitRetries, MAX_RATE_LIMIT_BACKOFF_SECONDS);
            userHandler.onUpdate(String.format("⏳ Rate limit hit. Pausing for %d seconds...\n",
                backoffSeconds));

            CompletableFuture.delayedExecutor(backoffSeconds, java.util.concurrent.TimeUnit.SECONDS)
                .execute(() -> {
                    if (isConversationActive && !isCancelled) {
                        userHandler.onUpdate("🔄 Resuming...\n");
                        continueConversation();
                    }
                });
        } else {
            isConversationActive = false;
            userHandler.onError(error);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Handle tool calls from streaming response.
     * Simplified version of handleToolCalls for use with streaming.
     */
    private void handleToolCallsFromStream(List<AnthropicPlatformApiProvider.ToolCall> toolCalls) {
        try {
            // Update UI with tool calling status
            String toolExecutionHeader = "\n\n🔧 **Executing tools...**\n";
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(toolExecutionHeader);
            });

            // Convert AnthropicPlatformApiProvider.ToolCall to JsonArray format expected by existing methods
            JsonArray toolCallsArray = new JsonArray();
            for (AnthropicPlatformApiProvider.ToolCall toolCall : toolCalls) {
                JsonObject toolCallObj = new JsonObject();
                toolCallObj.addProperty("id", toolCall.id);
                toolCallObj.addProperty("type", "function");

                JsonObject function = new JsonObject();
                function.addProperty("name", toolCall.name);
                function.addProperty("arguments", toolCall.arguments);
                toolCallObj.add("function", function);

                toolCallsArray.add(toolCallObj);
            }

            // Execute tools sequentially using existing infrastructure
            executeToolsSequentially(toolCallsArray, 0, new ArrayList<>());

        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls from stream: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Handle tool calls from OpenAI streaming response.
     */
    private void handleToolCallsFromOpenAIStream(List<OpenAIPlatformApiProvider.ToolCall> toolCalls) {
        try {
            String toolExecutionHeader = "\n\n🔧 **Executing tools...**\n";
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(toolExecutionHeader);
            });

            JsonArray toolCallsArray = new JsonArray();
            for (OpenAIPlatformApiProvider.ToolCall toolCall : toolCalls) {
                JsonObject toolCallObj = new JsonObject();
                toolCallObj.addProperty("id", toolCall.id);
                toolCallObj.addProperty("type", "function");

                JsonObject function = new JsonObject();
                function.addProperty("name", toolCall.name);
                function.addProperty("arguments", toolCall.arguments);
                toolCallObj.add("function", function);

                toolCallsArray.add(toolCallObj);
            }

            executeToolsSequentially(toolCallsArray, 0, new ArrayList<>());

        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls from OpenAI stream: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Handle tool calls from LMStudio streaming response.
     */
    private void handleToolCallsFromLMStudioStream(List<LMStudioProvider.ToolCall> toolCalls) {
        try {
            String toolExecutionHeader = "\n\n🔧 **Executing tools...**\n";
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(toolExecutionHeader);
            });

            JsonArray toolCallsArray = new JsonArray();
            for (LMStudioProvider.ToolCall toolCall : toolCalls) {
                JsonObject toolCallObj = new JsonObject();
                toolCallObj.addProperty("id", toolCall.id);
                toolCallObj.addProperty("type", "function");

                JsonObject function = new JsonObject();
                function.addProperty("name", toolCall.name);
                function.addProperty("arguments", toolCall.arguments);
                toolCallObj.add("function", function);

                toolCallsArray.add(toolCallObj);
            }

            executeToolsSequentially(toolCallsArray, 0, new ArrayList<>());

        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls from LMStudio stream: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Handle conversation end from streaming (no tool calls).
     */
    private void handleConversationEndFromStream(String fullText) {
        isConversationActive = false;

        // Pass the accumulated response text to onComplete
        String responseText = fullText != null ? fullText : "";

        javax.swing.SwingUtilities.invokeLater(() -> {
            userHandler.onComplete(responseText);
        });

        // Notify completion callback
        if (onCompletionCallback != null) {
            onCompletionCallback.run();
        }
    }

    /**
     * Handle the LLM response and determine next action based on finish_reason
     */
    private void handleLLMResponse(String rawResponse) {
        try {
            // Check cancellation before processing response
            if (isCancelled) {
                return;
            }
            
            Msg.debug(this, "Raw LLM response: " + (rawResponse != null ? rawResponse : "NULL"));
            
            // Validate response is not null or empty
            if (rawResponse == null || rawResponse.trim().isEmpty()) {
                throw new IllegalArgumentException("LLM response is null or empty");
            }
            
            // Parse the complete response including metadata
            JsonElement responseElement = JsonParser.parseString(rawResponse);
            if (responseElement == null || responseElement.isJsonNull()) {
                throw new IllegalArgumentException("LLM response parsed to null JSON");
            }
            
            if (!responseElement.isJsonObject()) {
                throw new IllegalArgumentException("LLM response is not a JSON object: " + responseElement.getClass().getSimpleName());
            }
            
            JsonObject responseObj = responseElement.getAsJsonObject();
            
            // Extract finish_reason from choices array
            String finishReason = extractFinishReason(responseObj);
            JsonObject assistantMessage = extractAssistantMessage(responseObj);
            
            Msg.debug(this, "LLM finish_reason: " + finishReason);
            
            if ("tool_calls".equals(finishReason) || "tool_use".equals(finishReason)) {
                handleToolCalls(assistantMessage, rawResponse);
            } else if ("stop".equals(finishReason) || "unknown".equals(finishReason)) {
                // Handle normal completion (no tools needed) or unknown finish_reason
                handleConversationEnd(assistantMessage);
            } else {
                // Other finish_reason types (length, content_filter, etc.)
                Msg.debug(this, "LLM finished with reason: " + finishReason + ", ending conversation");
                handleConversationEnd(assistantMessage);
            }
            
        } catch (Exception e) {
            Msg.error(this, "Error handling LLM response: " + e.getMessage());
            Msg.error(this, "Response content: " + (rawResponse != null ? rawResponse.substring(0, Math.min(500, rawResponse.length())) : "NULL"));
            isConversationActive = false;
            userHandler.onError(e);
            
            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }
    
    /**
     * Extract finish_reason from the LLM response
     */
    private String extractFinishReason(JsonObject responseObj) {
        try {
            if (responseObj != null && responseObj.has("choices")) {
                JsonElement choicesElement = responseObj.get("choices");
                if (choicesElement != null && !choicesElement.isJsonNull() && choicesElement.isJsonArray()) {
                    JsonArray choices = choicesElement.getAsJsonArray();
                    if (choices.size() > 0) {
                        JsonElement firstChoiceElement = choices.get(0);
                        if (firstChoiceElement != null && !firstChoiceElement.isJsonNull() && firstChoiceElement.isJsonObject()) {
                            JsonObject firstChoice = firstChoiceElement.getAsJsonObject();
                            if (firstChoice.has("finish_reason")) {
                                JsonElement finishReasonElement = firstChoice.get("finish_reason");
                                if (finishReasonElement != null && !finishReasonElement.isJsonNull()) {
                                    return finishReasonElement.getAsString();
                                }
                            }
                        }
                    }
                }
            }
            return "unknown";
        } catch (Exception e) {
            Msg.warn(this, "Could not extract finish_reason: " + e.getMessage());
            return "unknown";
        }
    }
    
    /**
     * Extract the assistant message from the LLM response
     */
    private JsonObject extractAssistantMessage(JsonObject responseObj) {
        try {
            if (responseObj != null && responseObj.has("choices")) {
                JsonElement choicesElement = responseObj.get("choices");
                if (choicesElement != null && !choicesElement.isJsonNull() && choicesElement.isJsonArray()) {
                    JsonArray choices = choicesElement.getAsJsonArray();
                    if (choices.size() > 0) {
                        JsonElement firstChoiceElement = choices.get(0);
                        if (firstChoiceElement != null && !firstChoiceElement.isJsonNull() && firstChoiceElement.isJsonObject()) {
                            JsonObject firstChoice = firstChoiceElement.getAsJsonObject();
                            if (firstChoice.has("message")) {
                                JsonElement messageElement = firstChoice.get("message");
                                if (messageElement != null && !messageElement.isJsonNull() && messageElement.isJsonObject()) {
                                    return messageElement.getAsJsonObject();
                                }
                            }
                        }
                    }
                }
            }
            // Fallback: try to find message directly
            if (responseObj != null && responseObj.has("message")) {
                JsonElement messageElement = responseObj.get("message");
                if (messageElement != null && !messageElement.isJsonNull() && messageElement.isJsonObject()) {
                    return messageElement.getAsJsonObject();
                }
            }
            return new JsonObject();
        } catch (Exception e) {
            Msg.warn(this, "Could not extract assistant message: " + e.getMessage());
            return new JsonObject();
        }
    }
    
    /**
     * Handle tool calls when finish_reason is "tool_calls"
     */
    private void handleToolCalls(JsonObject assistantMessage, String rawResponse) {
        try {
            // Create assistant message with tool calls
            String content = null;
            if (assistantMessage.has("content")) {
                JsonElement contentElement = assistantMessage.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                }
            }
            
            ChatMessage assistantMsg = new ChatMessage(
                ChatMessage.ChatMessageRole.ASSISTANT, 
                content
            );
            
            // Add tool calls to the assistant message
            if (assistantMessage.has("tool_calls")) {
                assistantMsg.setToolCalls(assistantMessage.getAsJsonArray("tool_calls"));
            }
            
            conversationHistory.add(assistantMsg);
            
            // Extract tool calls
            JsonArray toolCalls = null;
            if (assistantMessage.has("tool_calls")) {
                toolCalls = assistantMessage.getAsJsonArray("tool_calls");
            } else if (assistantMessage.has("content")) {
                // Try to parse tool calls from content
                // This line should not be reached now, but adding safety
                String contentStr = "";
                if (assistantMessage.has("content")) {
                    JsonElement contentElement = assistantMessage.get("content");
                    if (contentElement != null && !contentElement.isJsonNull()) {
                        contentStr = contentElement.getAsString();
                    }
                }
                JsonObject contentObj = JsonParser.parseString(contentStr).getAsJsonObject();
                if (contentObj.has("tool_calls")) {
                    toolCalls = contentObj.getAsJsonArray("tool_calls");
                }
            }
            
            if (toolCalls == null || toolCalls.size() == 0) {
                Msg.warn(this, "No tool calls found despite finish_reason being tool_calls");
                handleConversationEnd(assistantMessage);
                return;
            }
            
            // Display text response if present, before tool execution metadata
            if (content != null && !content.trim().isEmpty()) {
                String filteredContent = responseProcessor.filterThinkBlocks(content);
                if (filteredContent != null && !filteredContent.trim().isEmpty()) {
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        userHandler.onUpdate("\n" + filteredContent + "\n\n");
                    });
                }
            }
            
            // Update UI with tool calling status
            String toolExecutionHeader = "🔧 **Executing tools...**\n";
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(toolExecutionHeader);
            });
            
            // Execute tools and collect results
            executeToolsSequentially(toolCalls, 0, new ArrayList<>());
            
        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);
            
            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }
    
    /**
     * Execute tools sequentially and collect results
     */
    private void executeToolsSequentially(JsonArray toolCalls, int index, List<JsonObject> toolResults) {
        // Check cancellation before processing next tool
        if (isCancelled) {
            // Flush any collected results to prevent orphaned tool_calls in history.
            // Add placeholders for remaining tools that won't execute.
            for (int remaining = index; remaining < toolCalls.size(); remaining++) {
                String cancelledId;
                try {
                    cancelledId = extractToolCallId(toolCalls.get(remaining).getAsJsonObject());
                } catch (Exception e) {
                    cancelledId = "call_cancelled_" + remaining;
                }
                JsonObject cancelResult = new JsonObject();
                cancelResult.addProperty("tool_call_id", cancelledId);
                cancelResult.addProperty("role", "tool");
                cancelResult.addProperty("content", "Error: Tool execution was cancelled.");
                toolResults.add(cancelResult);
            }
            addToolResultsToConversation(toolResults);
            return;
        }

        if (index >= toolCalls.size()) {
            // All tools executed, add results to conversation and continue
            addToolResultsToConversation(toolResults);

            // Signal tool execution to handler
            userHandler.onToolsExecuted(toolCalls.size());

            // Add a small delay before making the next API call to avoid rapid sequential requests
            // that could trigger rate limits
            CompletableFuture.delayedExecutor(500, java.util.concurrent.TimeUnit.MILLISECONDS)
                .execute(() -> {
                    if (!isCancelled) {
                        continueConversation();
                    }
                });
            return;
        }
        
        JsonObject toolCall = toolCalls.get(index).getAsJsonObject();
        executeSingleTool(toolCall)
            .thenAccept(result -> {
                toolResults.add(result); // Always collect the result even if cancelled
                if (!isCancelled) {
                    // Add small delay between tool executions to be gentle on API rate limits
                    CompletableFuture.delayedExecutor(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                        .execute(() -> {
                            // Re-enter executeToolsSequentially which checks isCancelled and flushes
                            executeToolsSequentially(toolCalls, index + 1, toolResults);
                        });
                } else {
                    // Cancelled: flush current results + placeholders for remaining tools
                    executeToolsSequentially(toolCalls, index + 1, toolResults);
                }
            })
            .exceptionally(throwable -> {
                try {
                    if (!isCancelled) {
                        Msg.error(this, "Tool execution failed: " + throwable.getMessage());

                        // Safely extract tool call ID - don't let this throw and break the chain
                        String errorToolCallId;
                        try {
                            errorToolCallId = extractToolCallId(toolCall);
                        } catch (Exception idError) {
                            Msg.warn(this, "Failed to extract tool call ID in error handler: " + idError.getMessage());
                            errorToolCallId = "call_error_" + index;
                        }

                        // Create error result and continue
                        JsonObject errorResult = new JsonObject();
                        errorResult.addProperty("tool_call_id", errorToolCallId);
                        errorResult.addProperty("role", "tool");
                        errorResult.addProperty("content", "Error: " + throwable.getMessage());
                        toolResults.add(errorResult);

                        // Add same delay for error case to maintain consistent pacing
                        CompletableFuture.delayedExecutor(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                            .execute(() -> {
                                if (!isCancelled) {
                                    executeToolsSequentially(toolCalls, index + 1, toolResults);
                                }
                            });
                    }
                } catch (Exception outerError) {
                    // Last-resort catch: ensure the chain never breaks silently
                    Msg.error(this, "Critical error in tool execution error handler: " + outerError.getMessage());
                    // Still try to continue the chain with remaining tools
                    JsonObject fallbackResult = new JsonObject();
                    fallbackResult.addProperty("tool_call_id", "call_error_" + index);
                    fallbackResult.addProperty("role", "tool");
                    fallbackResult.addProperty("content", "Error: Internal error during tool execution");
                    toolResults.add(fallbackResult);

                    CompletableFuture.delayedExecutor(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                        .execute(() -> {
                            if (!isCancelled) {
                                executeToolsSequentially(toolCalls, index + 1, toolResults);
                            }
                        });
                }
                return null;
            });
    }
    
    /**
     * Execute a single tool and return the result
     */
    private CompletableFuture<JsonObject> executeSingleTool(JsonObject toolCall) {
        try {
            // Check cancellation before executing tool
            if (isCancelled) {
                return CompletableFuture.failedFuture(new Exception("Execution cancelled"));
            }

            String toolName = extractToolName(toolCall);
            JsonObject arguments = extractToolArguments(toolCall);
            String toolCallId = extractToolCallId(toolCall);

            // Update UI with current tool execution including parameters
            String paramDisplay = formatToolParameters(arguments);
            String executingMessage = "🛠️ Tool call in progress: *" + toolName + "(" + paramDisplay + ")*\n";
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate(executingMessage);
            });

            // Execute via ToolRegistry with proper transaction handling
            return executeToolWithTransaction(toolName, arguments)
                .thenApply(result -> {
                    // Check cancellation before processing result
                    if (isCancelled) {
                        throw new RuntimeException("Execution cancelled");
                    }

                    // Debug logging for development (keep for troubleshooting)
                    Msg.debug(this, String.format("Tool '%s' completed: success=%s, length=%d",
                        toolName, result.isSuccess(),
                        result.getContent() != null ? result.getContent().length() : 0));

                    // Don't show verbose tool results to user - they'll be included in LLM response
                    String paramDisplayComplete = formatToolParameters(arguments);
                    String completionMessage = "✓ Completed: *" + toolName + "(" + paramDisplayComplete + ")*\n";

                    javax.swing.SwingUtilities.invokeLater(() -> {
                        if (!isCancelled) {
                            userHandler.onUpdate(completionMessage);
                        }
                    });

                    // Create tool result for conversation
                    JsonObject toolResult = new JsonObject();
                    toolResult.addProperty("tool_call_id", toolCallId);
                    toolResult.addProperty("role", "tool");
                    toolResult.addProperty("content", result.getContent());

                    return toolResult;
                });

        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }
    
    /**
     * Add tool results to conversation history
     */
    private void addToolResultsToConversation(List<JsonObject> toolResults) {
        for (JsonObject result : toolResults) {
            // Safely extract content
            String content = "";
            if (result.has("content")) {
                JsonElement contentElement = result.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                }
            }
            
            // Safely extract tool_call_id
            String toolCallId = "";
            if (result.has("tool_call_id")) {
                JsonElement idElement = result.get("tool_call_id");
                if (idElement != null && !idElement.isJsonNull()) {
                    toolCallId = idElement.getAsString();
                }
            }
            
            ChatMessage toolMessage = new ChatMessage(ChatMessage.ChatMessageRole.TOOL, content);
            toolMessage.setToolCallId(toolCallId);
            conversationHistory.add(toolMessage);
        }
    }
    
    /**
     * Handle conversation end when finish_reason is "stop"
     */
    private void handleConversationEnd(JsonObject assistantMessage) {
        isConversationActive = false;
        
        try {
            // Extract and filter the final response
            String content = "";
            if (assistantMessage != null && assistantMessage.has("content")) {
                JsonElement contentElement = assistantMessage.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                }
            }
            
            // Handle case where content is null or empty
            if (content == null || content.trim().isEmpty()) {
                if (toolCallRound > 0) {
                    content = "Tool execution completed. Continuing analysis.";
                    Msg.info(this, "LLM response had no text content after " + toolCallRound + " tool rounds");
                } else {
                    content = "I'm ready to help you with this function analysis.";
                    Msg.info(this, "LLM response had no content, using default message");
                }
            }
            
            String filteredContent = responseProcessor.filterThinkBlocks(content);
            
            // Debug logging for final response
            Msg.info(this, String.format("Final LLM response: length=%d", 
                filteredContent != null ? filteredContent.length() : 0));
            if (filteredContent != null && filteredContent.length() > 0) {
                Msg.info(this, "Final response preview: " + 
                    (filteredContent.length() > 200 ? filteredContent.substring(0, 200) + "..." : filteredContent));
            }
            
            // Send only the final LLM response (tool execution messages were already sent individually)
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate("\n" + filteredContent);
                userHandler.onComplete("\n" + filteredContent);
            });
            
        } catch (Exception e) {
            Msg.error(this, "Error handling conversation end: " + e.getMessage());
            // Provide fallback response
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate("I encountered an error processing the response. Please try again.");
                userHandler.onComplete("Error processing response");
            });
        }
        
        // Notify completion callback
        if (onCompletionCallback != null) {
            onCompletionCallback.run();
        }
    }
    
    /**
     * Extract tool name from tool call
     */
    private String extractToolName(JsonObject toolCall) {
        if (toolCall.has("function")) {
            JsonObject function = toolCall.getAsJsonObject("function");
            if (function != null && function.has("name") && !function.get("name").isJsonNull()) {
                return function.get("name").getAsString();
            }
        } else if (toolCall.has("name") && !toolCall.get("name").isJsonNull()) {
            return toolCall.get("name").getAsString();
        }

        Msg.error(this, "No tool name found in tool call: " + toolCall.toString());
        throw new IllegalArgumentException("No tool name found in tool call: " + toolCall.toString());
    }
    
    /**
     * Extract arguments from tool call
     */
    private JsonObject extractToolArguments(JsonObject toolCall) {
        JsonObject arguments = new JsonObject();

        try {
            if (toolCall.has("function")) {
                JsonObject function = toolCall.getAsJsonObject("function");
                if (function != null && function.has("arguments") && !function.get("arguments").isJsonNull()) {
                    JsonElement argsElement = function.get("arguments");
                    if (argsElement.isJsonObject()) {
                        arguments = argsElement.getAsJsonObject();
                    } else if (argsElement.isJsonPrimitive()) {
                        // Parse string arguments
                        String argsStr = argsElement.getAsString();
                        if (argsStr != null && !argsStr.trim().isEmpty()) {
                            arguments = JsonParser.parseString(argsStr).getAsJsonObject();
                        }
                    }
                }
            } else if (toolCall.has("arguments") && !toolCall.get("arguments").isJsonNull()) {
                JsonElement argsElement = toolCall.get("arguments");
                if (argsElement.isJsonObject()) {
                    arguments = argsElement.getAsJsonObject();
                } else if (argsElement.isJsonPrimitive()) {
                    String argsStr = argsElement.getAsString();
                    if (argsStr != null && !argsStr.trim().isEmpty()) {
                        arguments = JsonParser.parseString(argsStr).getAsJsonObject();
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to extract arguments from tool call: " + e.getMessage());
            Msg.error(this, "Tool call JSON: " + toolCall.toString());
        }

        return arguments;
    }
    
    /**
     * Extract tool call ID from tool call.
     * Handles null, JsonNull, and empty string cases that can occur when
     * streaming doesn't fully capture the tool call ID.
     */
    private String extractToolCallId(JsonObject toolCall) {
        if (toolCall.has("id")) {
            JsonElement idElement = toolCall.get("id");
            if (idElement != null && !idElement.isJsonNull() && idElement.isJsonPrimitive()) {
                String id = idElement.getAsString();
                if (id != null && !id.isEmpty()) {
                    return id;
                }
            }
            // ID field exists but is null/empty - generate deterministic fallback
            Msg.warn(this, "Tool call has null/empty ID, generating fallback. Tool call: " + toolCall.toString());
        }
        // Generate a deterministic fallback ID using tool name when possible
        String toolName = "unknown";
        try {
            toolName = extractToolName(toolCall);
        } catch (Exception ignored) {
            // extractToolName can throw - use default
        }
        return "call_fallback_" + toolName + "_" + System.currentTimeMillis();
    }
    
    /**
     * Trim conversation history to prevent token overflow
     * Keeps the first message and ensures tool call/result pairs stay together
     */
    private void trimConversationHistory() {
        if (conversationHistory.size() <= MAX_CONVERSATION_HISTORY) {
            return; // No trimming needed
        }
        
        List<ChatMessage> trimmedHistory = new ArrayList<>();

        // Always keep the system message (index 0) and the first user message (original query)
        if (!conversationHistory.isEmpty()) {
            trimmedHistory.add(conversationHistory.get(0));  // System message

            // Find and keep the first USER message (the original query)
            for (int i = 1; i < conversationHistory.size(); i++) {
                ChatMessage msg = conversationHistory.get(i);
                if (ChatMessage.ChatMessageRole.USER.equals(msg.getRole())) {
                    trimmedHistory.add(msg);
                    break;  // Only keep the first user message
                }
            }
        }

        // Find a safe cutoff point that doesn't break tool call/result pairs
        int safeStartIndex = findSafeTrimPoint();
        
        // Add messages from safe point to end
        for (int i = safeStartIndex; i < conversationHistory.size(); i++) {
            trimmedHistory.add(conversationHistory.get(i));
        }
        
        // Replace conversation history
        conversationHistory.clear();
        conversationHistory.addAll(trimmedHistory);
        
        Msg.info(this, String.format("Trimmed conversation history to %d messages (safe tool-call trimming)", 
            conversationHistory.size()));
    }
    
    /**
     * Find a safe point to start trimming that doesn't break tool call/result pairs
     */
    private int findSafeTrimPoint() {
        int targetSize = MAX_CONVERSATION_HISTORY - 2; // -2 for system message + first user query we always keep
        int startFromEnd = Math.min(targetSize, conversationHistory.size() - 1);
        
        // Start from desired point and look backwards for a safe boundary
        for (int lookback = 0; lookback < startFromEnd; lookback++) {
            int candidateIndex = conversationHistory.size() - startFromEnd + lookback;
            
            // Check if this is a safe cut point (not in middle of tool call/result sequence)
            if (isSafeTrimPoint(candidateIndex)) {
                return candidateIndex;
            }
        }
        
        // Fallback: keep last half of conversation
        return Math.max(1, conversationHistory.size() / 2);
    }
    
    /**
     * Check if we can safely trim at this point without breaking tool call/result pairs.
     * Scans backwards to ensure no preceding assistant message has tool results
     * that extend past the candidate index.
     */
    private boolean isSafeTrimPoint(int index) {
        if (index <= 0 || index >= conversationHistory.size()) {
            return false;
        }

        ChatMessage currentMessage = conversationHistory.get(index);

        // Don't trim if current message is a tool result (it needs its tool call)
        if (ChatMessage.ChatMessageRole.TOOL.equals(currentMessage.getRole())) {
            return false;
        }

        // Scan backwards from the candidate to find the nearest assistant message with tool_calls.
        // If found, verify all its tool results are before the candidate index.
        for (int i = index - 1; i >= 0; i--) {
            ChatMessage msg = conversationHistory.get(i);

            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(msg.getRole()) &&
                msg.getToolCalls() != null && msg.getToolCalls().size() > 0) {

                // This assistant message has tool_calls. Check if any tool results
                // for it exist at or after the candidate index.
                int expectedResults = msg.getToolCalls().size();
                int foundResults = 0;
                for (int j = i + 1; j < conversationHistory.size(); j++) {
                    ChatMessage checkMsg = conversationHistory.get(j);
                    if (ChatMessage.ChatMessageRole.TOOL.equals(checkMsg.getRole())) {
                        foundResults++;
                        if (j >= index) {
                            // Tool result extends past the trim point - not safe
                            return false;
                        }
                    } else if (!ChatMessage.ChatMessageRole.TOOL.equals(checkMsg.getRole())) {
                        break; // Stop at non-tool message
                    }
                }

                // If we found fewer results than expected, some are missing
                // (validation will handle this, but don't trim here)
                if (foundResults < expectedResults) {
                    return false;
                }

                // This assistant message's tool results are all before the candidate - safe
                break;
            }

            // If we hit a user message, no need to look further back
            if (ChatMessage.ChatMessageRole.USER.equals(msg.getRole())) {
                break;
            }
        }

        return true;
    }

    /**
     * Validate and repair conversation history to prevent orphaned tool_calls.
     * Scans for assistant messages with tool_calls that lack matching tool result messages.
     * Called before each API call as a safety net.
     */
    private void validateAndRepairConversationHistory() {
        for (int i = 0; i < conversationHistory.size(); i++) {
            ChatMessage msg = conversationHistory.get(i);
            if (!ChatMessage.ChatMessageRole.ASSISTANT.equals(msg.getRole()) || msg.getToolCalls() == null) {
                continue;
            }

            JsonArray toolCalls = msg.getToolCalls();
            if (toolCalls.size() == 0) {
                continue;
            }

            // Collect all tool_call IDs from this assistant message
            List<String> expectedIds = new ArrayList<>();
            for (int tc = 0; tc < toolCalls.size(); tc++) {
                JsonObject toolCall = toolCalls.get(tc).getAsJsonObject();
                String id = null;
                if (toolCall.has("id")) {
                    JsonElement idEl = toolCall.get("id");
                    if (idEl != null && !idEl.isJsonNull() && idEl.isJsonPrimitive()) {
                        id = idEl.getAsString();
                    }
                }
                if (id != null && !id.isEmpty()) {
                    expectedIds.add(id);
                }
            }

            if (expectedIds.isEmpty()) {
                // All tool call IDs are null/empty - remove tool_calls entirely
                Msg.warn(this, "Removing tool_calls from assistant message at index " + i + ": all IDs are null/empty");
                msg.setToolCalls(null);
                continue;
            }

            // Check which IDs have matching tool result messages (look at messages after this one)
            List<String> foundIds = new ArrayList<>();
            for (int j = i + 1; j < conversationHistory.size(); j++) {
                ChatMessage resultMsg = conversationHistory.get(j);
                if (ChatMessage.ChatMessageRole.TOOL.equals(resultMsg.getRole()) && resultMsg.getToolCallId() != null) {
                    foundIds.add(resultMsg.getToolCallId());
                }
                // Stop scanning at the next assistant or user message
                if (ChatMessage.ChatMessageRole.ASSISTANT.equals(resultMsg.getRole()) ||
                    ChatMessage.ChatMessageRole.USER.equals(resultMsg.getRole())) {
                    break;
                }
            }

            // Check for missing results
            List<String> missingIds = new ArrayList<>();
            for (String expectedId : expectedIds) {
                if (!foundIds.contains(expectedId)) {
                    missingIds.add(expectedId);
                }
            }

            if (missingIds.isEmpty()) {
                continue; // All results present
            }

            if (missingIds.size() == expectedIds.size()) {
                // NO results found at all - remove tool_calls from assistant message
                Msg.warn(this, String.format(
                    "Removing orphaned tool_calls from assistant message at index %d: no matching tool results found for %d tool calls",
                    i, expectedIds.size()));
                msg.setToolCalls(null);
            } else {
                // SOME results missing - insert placeholder tool results
                Msg.warn(this, String.format(
                    "Inserting %d placeholder tool results for orphaned tool calls at index %d",
                    missingIds.size(), i));

                // Find insertion point: right after the last tool result for this assistant message
                int insertAt = i + 1;
                for (int j = i + 1; j < conversationHistory.size(); j++) {
                    ChatMessage checkMsg = conversationHistory.get(j);
                    if (ChatMessage.ChatMessageRole.TOOL.equals(checkMsg.getRole())) {
                        insertAt = j + 1;
                    } else {
                        break;
                    }
                }

                // Insert placeholders for missing IDs
                for (String missingId : missingIds) {
                    ChatMessage placeholder = new ChatMessage(ChatMessage.ChatMessageRole.TOOL,
                        "Error: Tool execution result was lost due to an internal error.");
                    placeholder.setToolCallId(missingId);
                    conversationHistory.add(insertAt, placeholder);
                    insertAt++;
                }
            }
        }
    }

    /**
     * Log conversation structure for debugging tool call/result matching issues.
     * Only outputs at debug level.
     */
    private void logConversationStructure() {
        if (conversationHistory.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder("Conversation structure (");
        sb.append(conversationHistory.size()).append(" messages):\n");
        for (int i = 0; i < conversationHistory.size(); i++) {
            ChatMessage msg = conversationHistory.get(i);
            sb.append(String.format("  [%d] role=%s", i, msg.getRole()));
            if (msg.getToolCalls() != null) {
                sb.append(String.format(" tool_calls=%d", msg.getToolCalls().size()));
            }
            if (msg.getToolCallId() != null) {
                sb.append(String.format(" tool_call_id=%s", msg.getToolCallId()));
            }
            int contentLen = msg.getContent() != null ? msg.getContent().length() : 0;
            sb.append(String.format(" content_len=%d", contentLen));
            sb.append("\n");
        }
        Msg.debug(this, sb.toString());
    }

    /**
     * Format tool parameters for display in execution logs
     */
    private String formatToolParameters(JsonObject arguments) {
        if (arguments == null || arguments.size() == 0) {
            return "";
        }
        
        StringBuilder params = new StringBuilder();
        boolean first = true;
        
        for (String key : arguments.keySet()) {
            if (!first) {
                params.append(", ");
            }
            first = false;
            
            JsonElement value = arguments.get(key);
            if (value.isJsonPrimitive()) {
                String strValue = value.getAsString();
                // Add quotes around string values for clarity
                if (value.getAsJsonPrimitive().isString()) {
                    params.append("\"").append(strValue).append("\"");
                } else {
                    params.append(strValue);
                }
            } else {
                // For complex objects, just show the key
                params.append(key).append("=").append(value.toString());
            }
        }
        
        return params.toString();
    }
    
    /**
     * Execute tool with proper Ghidra transaction handling via ToolRegistry
     * Run transaction on Swing EDT to match how Actions tab works
     */
    private CompletableFuture<ToolResult> executeToolWithTransaction(String toolName, JsonObject arguments) {
        CompletableFuture<ToolResult> future = new CompletableFuture<>();

        ghidra.program.model.listing.Program program = apiClient.getPlugin().getCurrentProgram();

        if (program == null) {
            // If no program is loaded, execute without transaction
            return toolRegistry.execute(toolName, arguments);
        }

        // Execute tool call on background thread to avoid blocking EDT
        CompletableFuture.runAsync(() -> {
            // Start transaction on EDT
            final int[] transaction = new int[1];
            try {
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    transaction[0] = program.startTransaction("Tool: " + toolName);
                });
            } catch (Exception e) {
                throw new RuntimeException("Failed to start transaction", e);
            }

            // Execute tool via ToolRegistry
            toolRegistry.execute(toolName, arguments)
                .thenAccept(result -> {
                    // End transaction on EDT
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        boolean success = result.isSuccess();
                        program.endTransaction(transaction[0], success);
                        future.complete(result);
                    });
                })
                .exceptionally(throwable -> {
                    // End transaction on EDT with failure
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        program.endTransaction(transaction[0], false);
                        Msg.error(this, "Tool execution failed: " + throwable.getMessage());
                        future.complete(ToolResult.error("Tool execution failed: " + throwable.getMessage()));
                    });
                    return null;
                });

        }).exceptionally(throwable -> {
            Msg.error(this, "Failed to start transaction: " + throwable.getMessage());
            future.complete(ToolResult.error("Failed to start transaction: " + throwable.getMessage()));
            return null;
        });

        return future;
    }

    /**
     * Get the current conversation history.
     * Useful for persisting ReAct conversations.
     *
     * @return Copy of conversation history
     */
    public List<ChatMessage> getConversationHistory() {
        return new ArrayList<>(conversationHistory);
    }
}