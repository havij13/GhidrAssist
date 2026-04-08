package ghidrassist.chat.transcript;

import com.google.gson.JsonObject;
import ghidra.util.Msg;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolExecutionObserver;
import ghidrassist.tools.api.ToolResult;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Append-only transcript service used for persistence, backfill, and rendering.
 */
public class TranscriptService implements ToolExecutionObserver {
    private final Connection connection;
    private final TranscriptArtifactStore artifactStore;
    private final TranscriptRenderer renderer;
    private volatile Consumer<Integer> sessionUpdateListener;

    public TranscriptService(Connection connection, Path artifactRoot) {
        this.connection = connection;
        this.artifactStore = new TranscriptArtifactStore(artifactRoot);
        this.renderer = new TranscriptRenderer();
    }

    public synchronized boolean hasEvents(int sessionId) {
        String sql = "SELECT 1 FROM GHChatTranscriptEvents WHERE session_id = ? LIMIT 1";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            return stmt.executeQuery().next();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to check transcript presence: " + e.getMessage());
            return false;
        }
    }

    public synchronized void ensureBackfilledFromMessages(String programHash, int sessionId,
                                                          List<PersistedChatMessage> messages) {
        if (sessionId <= 0 || messages == null || messages.isEmpty()) {
            return;
        }
        List<TranscriptEvent> existingEvents = loadEvents(sessionId);
        List<TranscriptEvent> conversationalEvents = filterConversationalEvents(existingEvents);
        int searchStart = 0;
        for (PersistedChatMessage message : messages) {
            TranscriptEventKind kind = switch (message.getRole()) {
                case "user" -> TranscriptEventKind.USER_MESSAGE;
                case "assistant" -> TranscriptEventKind.ASSISTANT_MESSAGE;
                case "error" -> TranscriptEventKind.SYSTEM_NOTICE;
                case "tool_call", "tool_response" -> TranscriptEventKind.TOOL_CALL_COMPLETED;
                default -> TranscriptEventKind.SYSTEM_NOTICE;
            };
            String title = switch (kind) {
                case USER_MESSAGE -> "User";
                case ASSISTANT_MESSAGE -> "Assistant";
                case TOOL_CALL_COMPLETED -> "Legacy Tool Activity";
                case SYSTEM_NOTICE -> "Legacy Event";
                default -> kind.getDbValue();
            };
            int matchedIndex = findBestConversationEventMatch(
                conversationalEvents, searchStart, kind, message.getContent(), message.getTimestamp(),
                message.getDbId(), message.getOrder());
            if (matchedIndex >= 0) {
                TranscriptEvent matchedEvent = conversationalEvents.get(matchedIndex);
                if (matchedEvent.getSourceMessageId() == null || matchedEvent.getSourceMessageOrder() == null) {
                    updateEventSourceLink(matchedEvent.getId(), message.getDbId(), message.getOrder());
                    conversationalEvents.set(matchedIndex, new TranscriptEvent(
                        matchedEvent.getId(),
                        matchedEvent.getSessionId(),
                        matchedEvent.getProgramHash(),
                        matchedEvent.getCorrelationId(),
                        matchedEvent.getParentEventId(),
                        matchedEvent.getKind(),
                        matchedEvent.getRole(),
                        matchedEvent.getTitle(),
                        matchedEvent.getContentText(),
                        matchedEvent.getPreviewText(),
                        matchedEvent.getMetadataJson(),
                        matchedEvent.getArtifactId(),
                        message.getDbId(),
                        message.getOrder(),
                        matchedEvent.getCreatedAt()
                    ));
                    Msg.info(this, "Linked transcript event " + matchedEvent.getId()
                        + " to message " + message.getDbId() + " (order=" + message.getOrder() + ")");
                }
                removeLaterSourceLinkedDuplicates(sessionId, conversationalEvents, matchedIndex,
                    kind, message.getContent(), message.getDbId(), message.getOrder());
                searchStart = matchedIndex + 1;
                continue;
            }
            appendEvent(sessionId, programHash, null, null, kind, message.getRole(), title,
                message.getContent(), message.getContent(), message.getNativeMessageData(),
                null, message.getDbId(), message.getOrder(), message.getTimestamp(), false);
            TranscriptEvent appendedEvent = new TranscriptEvent(
                -1L,
                sessionId,
                programHash,
                null,
                null,
                kind,
                message.getRole(),
                title,
                message.getContent(),
                message.getContent(),
                message.getNativeMessageData(),
                null,
                message.getDbId(),
                message.getOrder(),
                message.getTimestamp()
            );
            existingEvents.add(appendedEvent);
            conversationalEvents.add(appendedEvent);
            searchStart = conversationalEvents.size();
        }
    }

    public synchronized void ensureBackfilledFromReActMessages(String programHash, int sessionId,
                                                               List<ghidrassist.apiprovider.ChatMessage> messages) {
        if (sessionId <= 0 || hasEvents(sessionId) || messages == null || messages.isEmpty()) {
            return;
        }
        for (ghidrassist.apiprovider.ChatMessage message : messages) {
            TranscriptEventKind kind = "user".equals(message.getRole())
                ? TranscriptEventKind.USER_MESSAGE
                : TranscriptEventKind.ASSISTANT_MESSAGE;
            String title = kind == TranscriptEventKind.USER_MESSAGE ? "User" : "Assistant";
            appendEvent(sessionId, programHash, null, null, kind, message.getRole(), title,
                message.getContent(), message.getContent(), null, null, null, null, null, false);
        }
    }

    public void appendUserMessage(int sessionId, String programHash, String content, Timestamp createdAt) {
        appendUserMessage(sessionId, programHash, content, createdAt, null, null);
    }

    public void appendUserMessage(int sessionId, String programHash, String content, Timestamp createdAt,
                                  Integer sourceMessageId, Integer sourceMessageOrder) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.USER_MESSAGE,
            "user", "User", content, content, null, null, sourceMessageId, sourceMessageOrder, createdAt, true);
    }

    public void appendAssistantMessage(int sessionId, String programHash, String content, Timestamp createdAt) {
        appendAssistantMessage(sessionId, programHash, content, createdAt, null, null);
    }

    public void appendAssistantMessage(int sessionId, String programHash, String content, Timestamp createdAt,
                                       Integer sourceMessageId, Integer sourceMessageOrder) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.ASSISTANT_MESSAGE,
            "assistant", "Assistant", content, content, null, null, sourceMessageId, sourceMessageOrder, createdAt, true);
    }

    public void appendSystemNotice(int sessionId, String programHash, String title, String content) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.SYSTEM_NOTICE,
            "system", title, content, content, null, null, null, null, null, true);
    }

    public void appendDocumentSnapshot(int sessionId, String programHash, String title, String content) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.DOCUMENT_SNAPSHOT,
            "assistant", title, content, content, null, null, null, null, null, true);
    }

    public void appendContextCompacted(int sessionId, String programHash, String summary) {
        appendContextCompacted(sessionId, programHash, summary, null);
    }

    public void appendContextCompacted(int sessionId, String programHash, String summary, String metadataJson) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.CONTEXT_COMPACTED,
            "system", "Conversation summarized for context budget", summary, summary, metadataJson, null, null, null, null, true);
    }

    public void appendApprovalRequested(int sessionId, String programHash, String correlationId, String requestId,
                                        String toolName, String toolSource, String riskTier, JsonObject args) {
        appendEvent(sessionId, programHash, correlationId, null, TranscriptEventKind.APPROVAL_REQUESTED,
            "system", "Approval required: " + toolName,
            args != null ? args.toString() : "{}", args != null ? args.toString() : "{}",
            buildApprovalRequestedMetadata(requestId, toolName, toolSource, riskTier, args), null, null, null, null, true);
    }

    public void appendApprovalDecision(int sessionId, String programHash, String correlationId, String requestId,
                                       String toolName, String decision, String riskTier, String scope,
                                       String toolSource) {
        appendEvent(sessionId, programHash, correlationId, null, TranscriptEventKind.APPROVAL_DECISION,
            "system", "Approval decision: " + toolName,
            decision, decision, buildApprovalDecisionMetadata(requestId, toolName, toolSource, riskTier, decision, scope),
            null, null, null, null, true);
    }

    public synchronized String renderSessionHtml(int sessionId) {
        return renderer.renderDocument(loadEvents(sessionId));
    }

    public synchronized String renderSessionHtmlFragment(int sessionId) {
        return renderer.renderFragment(loadEvents(sessionId));
    }

    public synchronized void toggleToolGroupExpansion(String correlationId) {
        renderer.toggleToolGroup(correlationId);
    }

    public synchronized List<TranscriptEvent> loadEvents(int sessionId) {
        List<TranscriptEvent> events = new ArrayList<>();
        String sql = """
            SELECT id, session_id, program_hash, correlation_id, parent_event_id, event_kind, role,
                   title, content_text, preview_text, metadata_json, artifact_id,
                   source_message_id, source_message_order, created_at
            FROM GHChatTranscriptEvents
            WHERE session_id = ?
            ORDER BY id ASC
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                long parentEventId = rs.getLong("parent_event_id");
                events.add(new TranscriptEvent(
                    rs.getLong("id"),
                    rs.getInt("session_id"),
                    rs.getString("program_hash"),
                    rs.getString("correlation_id"),
                    rs.wasNull() ? null : parentEventId,
                    TranscriptEventKind.fromDbValue(rs.getString("event_kind")),
                    rs.getString("role"),
                    rs.getString("title"),
                    rs.getString("content_text"),
                    rs.getString("preview_text"),
                    rs.getString("metadata_json"),
                    rs.getString("artifact_id"),
                    getNullableInt(rs, "source_message_id"),
                    getNullableInt(rs, "source_message_order"),
                    rs.getTimestamp("created_at")
                ));
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to load transcript events: " + e.getMessage());
        }
        return events;
    }

    public void setSessionUpdateListener(Consumer<Integer> sessionUpdateListener) {
        this.sessionUpdateListener = sessionUpdateListener;
    }

    @Override
    public void onToolCallRequested(int sessionId, String programHash, String correlationId,
                                    Tool tool, JsonObject args) {
        appendEvent(sessionId, programHash, correlationId, null, TranscriptEventKind.TOOL_CALL_REQUESTED,
            "tool", tool.getName(), args != null ? args.toString() : "{}",
            args != null ? args.toString() : "{}", buildToolMetadata(tool, args), null, null, null, null, true);
    }

    @Override
    public void onToolCallStarted(int sessionId, String programHash, String correlationId,
                                  Tool tool, JsonObject args) {
        Long parentId = findMostRecentEventId(sessionId, correlationId, TranscriptEventKind.TOOL_CALL_REQUESTED);
        appendEvent(sessionId, programHash, correlationId, parentId, TranscriptEventKind.TOOL_CALL_STARTED,
            "tool", tool.getName(), "Executing...", "Executing...", buildToolMetadata(tool, args), null, null, null, null, true);
    }

    @Override
    public void onToolCallCompleted(int sessionId, String programHash, String correlationId,
                                    Tool tool, JsonObject args, ToolResult result) {
        TranscriptArtifactStore.StoredArtifact artifact =
            artifactStore.maybeStore(sessionId, "tool_result", result != null ? result.getContentOrError() : "");
        Long parentId = findMostRecentEventId(sessionId, correlationId, TranscriptEventKind.TOOL_CALL_STARTED);
        long eventId = appendEvent(sessionId, programHash, correlationId, parentId,
            TranscriptEventKind.TOOL_CALL_COMPLETED, "tool", tool.getName(),
            artifact.getInlineContent(), artifact.getPreviewText(),
            buildToolMetadata(tool, args), artifact.getArtifactId(), null, null, null, true);
        if (artifact.getArtifactId() != null) {
            persistArtifact(eventId, sessionId, artifact);
        }
    }

    @Override
    public void onToolCallFailed(int sessionId, String programHash, String correlationId,
                                 Tool tool, JsonObject args, String errorMessage) {
        Long parentId = findMostRecentEventId(sessionId, correlationId, TranscriptEventKind.TOOL_CALL_STARTED);
        appendEvent(sessionId, programHash, correlationId, parentId, TranscriptEventKind.TOOL_CALL_FAILED,
            "tool", tool.getName(), errorMessage, errorMessage, buildToolMetadata(tool, args), null, null, null, null, true);
    }

    private synchronized long appendEvent(int sessionId, String programHash, String correlationId,
                                          Long parentEventId, TranscriptEventKind kind, String role,
                                          String title, String contentText, String previewText,
                                          String metadataJson, String artifactId,
                                          Integer sourceMessageId, Integer sourceMessageOrder,
                                          Timestamp createdAt, boolean touchSession) {
        String sql = """
            INSERT INTO GHChatTranscriptEvents (
                session_id, program_hash, correlation_id, parent_event_id, event_kind, role, title,
                content_text, preview_text, metadata_json, artifact_id,
                source_message_id, source_message_order, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setInt(1, sessionId);
            stmt.setString(2, programHash);
            stmt.setString(3, correlationId);
            if (parentEventId != null) {
                stmt.setLong(4, parentEventId);
            } else {
                stmt.setNull(4, java.sql.Types.INTEGER);
            }
            stmt.setString(5, kind.getDbValue());
            stmt.setString(6, role);
            stmt.setString(7, title);
            stmt.setString(8, contentText);
            stmt.setString(9, previewText);
            stmt.setString(10, metadataJson);
            stmt.setString(11, artifactId);
            if (sourceMessageId != null) {
                stmt.setInt(12, sourceMessageId);
            } else {
                stmt.setNull(12, java.sql.Types.INTEGER);
            }
            if (sourceMessageOrder != null) {
                stmt.setInt(13, sourceMessageOrder);
            } else {
                stmt.setNull(13, java.sql.Types.INTEGER);
            }
            stmt.setTimestamp(14, createdAt);
            stmt.executeUpdate();

            if (touchSession) {
                touchSession(sessionId);
            }
            notifySessionUpdated(sessionId);

            ResultSet keys = stmt.getGeneratedKeys();
            if (keys.next()) {
                return keys.getLong(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to append transcript event: " + e.getMessage());
        }
        return -1;
    }

    private void notifySessionUpdated(int sessionId) {
        Consumer<Integer> listener = sessionUpdateListener;
        if (listener != null) {
            listener.accept(sessionId);
        }
    }

    private synchronized void persistArtifact(long eventId, int sessionId,
                                              TranscriptArtifactStore.StoredArtifact artifact) {
        String sql = """
            INSERT OR REPLACE INTO GHChatArtifacts (
                artifact_id, session_id, event_id, artifact_type, storage_path, preview_text, byte_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, artifact.getArtifactId());
            stmt.setInt(2, sessionId);
            stmt.setLong(3, eventId);
            stmt.setString(4, artifact.getArtifactType());
            stmt.setString(5, artifact.getStoragePath());
            stmt.setString(6, artifact.getPreviewText());
            stmt.setInt(7, artifact.getByteSize());
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to persist artifact metadata: " + e.getMessage());
        }
    }

    private synchronized Long findMostRecentEventId(int sessionId, String correlationId, TranscriptEventKind kind) {
        String sql = """
            SELECT id FROM GHChatTranscriptEvents
            WHERE session_id = ? AND correlation_id = ? AND event_kind = ?
            ORDER BY id DESC LIMIT 1
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            stmt.setString(2, correlationId);
            stmt.setString(3, kind.getDbValue());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getLong("id");
            }
        } catch (SQLException e) {
            Msg.warn(this, "Failed to resolve parent transcript event: " + e.getMessage());
        }
        return null;
    }

    private List<TranscriptEvent> filterConversationalEvents(List<TranscriptEvent> events) {
        List<TranscriptEvent> filtered = new ArrayList<>();
        if (events == null || events.isEmpty()) {
            return filtered;
        }
        for (TranscriptEvent event : events) {
            if (event == null || event.getKind() == null) {
                continue;
            }
            switch (event.getKind()) {
                case USER_MESSAGE, ASSISTANT_MESSAGE, SYSTEM_NOTICE, TOOL_CALL_COMPLETED -> filtered.add(event);
                default -> {
                }
            }
        }
        return filtered;
    }

    private int findBestConversationEventMatch(List<TranscriptEvent> events, int startIndex,
                                               TranscriptEventKind kind, String content, Timestamp timestamp,
                                               Integer sourceMessageId, Integer sourceMessageOrder) {
        int sourceMatchedIndex = findMatchingConversationEventBySource(
            events, startIndex, kind, sourceMessageId, sourceMessageOrder);
        int unlinkedTimestampMatch = findMatchingConversationEventUnlinked(
            events, startIndex, kind, content, timestamp, true);
        if (unlinkedTimestampMatch >= 0 &&
            (sourceMatchedIndex < 0 || unlinkedTimestampMatch < sourceMatchedIndex)) {
            return unlinkedTimestampMatch;
        }
        int unlinkedContentMatch = findMatchingConversationEventUnlinked(
            events, startIndex, kind, content, timestamp, false);
        if (unlinkedContentMatch >= 0 &&
            (sourceMatchedIndex < 0 || unlinkedContentMatch < sourceMatchedIndex)) {
            return unlinkedContentMatch;
        }
        if (sourceMatchedIndex >= 0) {
            return sourceMatchedIndex;
        }
        return findMatchingConversationEvent(events, startIndex, kind, content, timestamp);
    }

    private int findMatchingConversationEvent(List<TranscriptEvent> events, int startIndex,
                                              TranscriptEventKind kind, String content, Timestamp timestamp) {
        if (events == null || events.isEmpty()) {
            return -1;
        }
        int safeStart = Math.max(0, startIndex);
        String normalizedContent = content != null ? content.trim() : "";
        for (int i = safeStart; i < events.size(); i++) {
            TranscriptEvent event = events.get(i);
            if (!eventMatches(event, kind, normalizedContent, timestamp, true)) {
                continue;
            }
            return i;
        }
        for (int i = safeStart; i < events.size(); i++) {
            TranscriptEvent event = events.get(i);
            if (!eventMatches(event, kind, normalizedContent, timestamp, false)) {
                continue;
            }
            return i;
        }
        return -1;
    }

    private int findMatchingConversationEventUnlinked(List<TranscriptEvent> events, int startIndex,
                                                      TranscriptEventKind kind, String content, Timestamp timestamp,
                                                      boolean requireTimestampMatch) {
        if (events == null || events.isEmpty()) {
            return -1;
        }
        int safeStart = Math.max(0, startIndex);
        String normalizedContent = content != null ? content.trim() : "";
        for (int i = safeStart; i < events.size(); i++) {
            TranscriptEvent event = events.get(i);
            if (event == null || event.getKind() != kind) {
                continue;
            }
            if (event.getSourceMessageId() != null || event.getSourceMessageOrder() != null) {
                continue;
            }
            if (!eventMatches(event, kind, normalizedContent, timestamp, requireTimestampMatch)) {
                continue;
            }
            return i;
        }
        return -1;
    }

    private int findMatchingConversationEventBySource(List<TranscriptEvent> events, int startIndex,
                                                      TranscriptEventKind kind, Integer sourceMessageId,
                                                      Integer sourceMessageOrder) {
        if (events == null || events.isEmpty()) {
            return -1;
        }
        int safeStart = Math.max(0, startIndex);
        for (int i = safeStart; i < events.size(); i++) {
            TranscriptEvent event = events.get(i);
            if (event == null || event.getKind() != kind) {
                continue;
            }
            if (sourceMessageId != null && sourceMessageId.equals(event.getSourceMessageId())) {
                return i;
            }
            if (sourceMessageOrder != null && sourceMessageOrder.equals(event.getSourceMessageOrder())) {
                return i;
            }
        }
        return -1;
    }

    private void updateEventSourceLink(long eventId, Integer sourceMessageId, Integer sourceMessageOrder) {
        if (eventId <= 0 || (sourceMessageId == null && sourceMessageOrder == null)) {
            return;
        }
        String sql = """
            UPDATE GHChatTranscriptEvents
            SET source_message_id = COALESCE(source_message_id, ?),
                source_message_order = COALESCE(source_message_order, ?)
            WHERE id = ?
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            if (sourceMessageId != null) {
                stmt.setInt(1, sourceMessageId);
            } else {
                stmt.setNull(1, java.sql.Types.INTEGER);
            }
            if (sourceMessageOrder != null) {
                stmt.setInt(2, sourceMessageOrder);
            } else {
                stmt.setNull(2, java.sql.Types.INTEGER);
            }
            stmt.setLong(3, eventId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to update transcript/source message link: " + e.getMessage());
        }
    }

    private void removeLaterSourceLinkedDuplicates(int sessionId, List<TranscriptEvent> events, int canonicalIndex,
                                                   TranscriptEventKind kind, String content,
                                                   Integer sourceMessageId, Integer sourceMessageOrder) {
        if (events == null || events.isEmpty() || canonicalIndex < 0 || canonicalIndex >= events.size()) {
            return;
        }
        if (sourceMessageId == null && sourceMessageOrder == null) {
            return;
        }

        TranscriptEvent canonical = events.get(canonicalIndex);
        String normalizedContent = content != null ? content.trim() : "";
        for (int i = events.size() - 1; i > canonicalIndex; i--) {
            TranscriptEvent event = events.get(i);
            if (event == null || event.getKind() != kind) {
                continue;
            }
            String eventContent = event.getContentText() != null ? event.getContentText().trim() : "";
            if (!eventContent.equals(normalizedContent)) {
                continue;
            }
            boolean sameSource = (sourceMessageId != null && sourceMessageId.equals(event.getSourceMessageId()))
                || (sourceMessageOrder != null && sourceMessageOrder.equals(event.getSourceMessageOrder()));
            if (!sameSource || event.getId() == canonical.getId()) {
                continue;
            }
            deleteEvent(event.getId());
            events.remove(i);
            Msg.info(this, "Removed duplicate transcript event " + event.getId()
                + " for message " + sourceMessageId + " in session " + sessionId);
        }
    }

    private Integer getNullableInt(ResultSet rs, String columnName) throws SQLException {
        int value = rs.getInt(columnName);
        return rs.wasNull() ? null : value;
    }

    private boolean eventMatches(TranscriptEvent event, TranscriptEventKind kind, String normalizedContent,
                                 Timestamp timestamp, boolean requireTimestampMatch) {
        if (event == null || event.getKind() != kind) {
            return false;
        }
        String eventContent = event.getContentText() != null ? event.getContentText().trim() : "";
        if (!eventContent.equals(normalizedContent)) {
            return false;
        }
        return !requireTimestampMatch || timestampsClose(event.getCreatedAt(), timestamp);
    }

    private boolean timestampsClose(Timestamp a, Timestamp b) {
        if (a == null || b == null) {
            return false;
        }
        return Math.abs(a.getTime() - b.getTime()) < 10000;
    }

    private void touchSession(int sessionId) {
        String sql = "UPDATE GHChatHistory SET last_update = CURRENT_TIMESTAMP WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to touch session for transcript event: " + e.getMessage());
        }
    }

    private void deleteEvent(long eventId) {
        if (eventId <= 0) {
            return;
        }
        String sql = "DELETE FROM GHChatTranscriptEvents WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setLong(1, eventId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to delete duplicate transcript event " + eventId + ": " + e.getMessage());
        }
    }

    private String buildToolMetadata(Tool tool, JsonObject args) {
        JsonObject metadata = new JsonObject();
        metadata.addProperty("tool", tool.getName());
        metadata.addProperty("source", tool.getSource());
        if (args != null) {
            metadata.add("args", args.deepCopy());
        }
        return metadata.toString();
    }

    private String buildApprovalRequestedMetadata(String requestId, String toolName, String toolSource,
                                                  String riskTier, JsonObject args) {
        JsonObject metadata = new JsonObject();
        metadata.addProperty("request_id", requestId);
        metadata.addProperty("tool", toolName);
        metadata.addProperty("source", toolSource);
        metadata.addProperty("risk_tier", riskTier);
        metadata.addProperty("pending", true);
        if (args != null) {
            metadata.add("args", args.deepCopy());
        }
        return metadata.toString();
    }

    private String buildApprovalDecisionMetadata(String requestId, String toolName, String toolSource,
                                                 String riskTier, String decision, String scope) {
        JsonObject metadata = new JsonObject();
        metadata.addProperty("request_id", requestId);
        metadata.addProperty("tool", toolName);
        metadata.addProperty("source", toolSource);
        if (riskTier != null) {
            metadata.addProperty("risk_tier", riskTier);
        }
        if (decision != null) {
            metadata.addProperty("decision", decision);
        }
        if (scope != null) {
            metadata.addProperty("scope", scope);
        }
        return metadata.toString();
    }
}
