package ghidrassist.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;
import ghidrassist.services.QueryService;
import ghidrassist.services.symgraph.SymGraphService;
import ghidrassist.services.symgraph.SymGraphModels.*;
import ghidrassist.ui.tabs.SymGraphTab;
import ghidrassist.workers.SymGraphApplyWorker;
import ghidrassist.workers.SymGraphPullWorker;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller for SymGraph operations.
 * Handles query, push, pull, and apply operations for symbol sharing.
 *
 * Extracted from TabController as part of decomposition refactoring.
 */
public class SymGraphController {

    private final GhidrAssistPlugin plugin;
    private final AnalysisDB analysisDB;
    private final QueryService queryService;
    private final Runnable refreshChatHistoryCallback;
    private SymGraphService symGraphService;
    private SymGraphTab symGraphTab;
    private SymGraphApplyWorker applyWorker;
    private SymGraphPullWorker pullWorker;
    private Map<String, Long> externalAddressMap;
    private final List<Map<String, Object>> pushPreviewSymbols = new ArrayList<>();
    private final List<Map<String, Object>> pushPreviewDocuments = new ArrayList<>();
    private Map<String, Object> pushPreviewGraphData;
    private List<Map<String, Object>> pendingPushDocuments = new ArrayList<>();
    private List<DocumentSummary> pendingApplyDocuments = new ArrayList<>();
    private String pendingPushScope;
    private boolean pendingPushSymbols;
    private boolean pendingPushGraph;
    private String pendingPushVisibility = "public";
    private String pendingApplyBaseMessage;

    public SymGraphController(
            GhidrAssistPlugin plugin,
            AnalysisDB analysisDB,
            QueryService queryService,
            Runnable refreshChatHistoryCallback) {
        this.plugin = plugin;
        this.analysisDB = analysisDB;
        this.queryService = queryService;
        this.refreshChatHistoryCallback = refreshChatHistoryCallback;
    }

    // ==== Tab Registration ====

    public void setSymGraphTab(SymGraphTab tab) {
        this.symGraphTab = tab;
        if (this.symGraphService == null) {
            this.symGraphService = new SymGraphService();
        }
    }

    // ==== Query Operations ====

    /**
     * Handle SymGraph query request.
     */
    public void handleQuery() {
        if (symGraphTab == null || symGraphService == null) {
            Msg.showError(this, null, "Error", "SymGraph tab not initialized");
            return;
        }

        String sha256 = getProgramSHA256();
        if (sha256 == null) {
            Msg.showInfo(this, symGraphTab, "No Binary", "No binary loaded or unable to compute hash.");
            return;
        }

        symGraphTab.setQueryStatus("Checking...", false);
        symGraphTab.hideStats();
        symGraphTab.setOpenBinaryUrl(null);
        symGraphTab.setButtonsEnabled(false);

        Task task = new Task("Query SymGraph", true, true, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    QueryResult result = symGraphService.queryBinary(sha256, null, true);

                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.setButtonsEnabled(true);
                        if (result.getError() != null) {
                            symGraphTab.setQueryStatus("Error: " + result.getError(), false);
                            symGraphTab.setOpenBinaryUrl(null);
                        } else if (result.isExists()) {
                            symGraphTab.setQueryStatus("Found in SymGraph", true);
                            symGraphTab.setOpenBinaryUrl(symGraphService.getBinaryUrl(sha256));
                            if (result.getStats() != null) {
                                BinaryStats stats = result.getStats();
                                symGraphTab.setStats(
                                    stats.getSymbolCount(),
                                    stats.getFunctionCount(),
                                    stats.getGraphNodeCount(),
                                    stats.getLastQueriedAt(),
                                    result.getRevisions(),
                                    result.getLatestRevision(),
                                    result.getSelectedRevision()
                                );
                            }
                        } else {
                            symGraphTab.setQueryStatus("Not found in SymGraph", false);
                            symGraphTab.setOpenBinaryUrl(null);
                            symGraphTab.hideStats();
                        }
                    });
                } catch (Exception e) {
                    Msg.error(this, "Query error: " + e.getMessage(), e);
                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.setButtonsEnabled(true);
                        symGraphTab.setQueryStatus("Error: " + e.getMessage(), false);
                        symGraphTab.setOpenBinaryUrl(null);
                    });
                }
            }
        };
        TaskLauncher.launch(task);
    }

    // ==== Push Operations ====

    /**
     * Handle SymGraph push request.
     */
    public void handlePushPreview() {
        if (symGraphTab == null) {
            Msg.showError(this, null, "Error", "SymGraph tab not initialized");
            return;
        }

        String sha256 = getProgramSHA256();
        if (sha256 == null) {
            Msg.showInfo(this, symGraphTab, "No Binary", "No binary loaded or unable to compute hash.");
            return;
        }

        SymGraphTab.PushConfig pushConfig = symGraphTab.getPushConfig();
        String scope = pushConfig.getScope();
        List<String> selectedTypes = pushConfig.getSymbolTypes();
        String nameFilter = pushConfig.getNameFilter() != null ? pushConfig.getNameFilter().trim().toLowerCase() : "";
        boolean includeGraph = pushConfig.isPushGraph();

        List<Map<String, Object>> symbols = collectLocalSymbols(scope);
        if (selectedTypes.isEmpty()) {
            symbols.clear();
        } else {
            symbols.removeIf(symbol -> !matchesPushTypeFilter(symbol, selectedTypes));
        }
        if (!nameFilter.isEmpty()) {
            symbols.removeIf(symbol -> !matchesNameFilter(symbol, nameFilter));
        }
        List<Map<String, Object>> documents = queryService != null
                ? queryService.listDocumentPushCandidates()
                : new ArrayList<>();
        if (!nameFilter.isEmpty()) {
            documents.removeIf(document -> {
                Object title = document.get("title");
                return !(title instanceof String) || !((String) title).toLowerCase().contains(nameFilter);
            });
        }

        if (includeGraph) {
            externalAddressMap = buildExternalAddressMap();
        }
        Map<String, Object> graphData = includeGraph ? collectLocalGraph(scope) : null;
        int graphNodes = graphData != null ? getCollectionSize(graphData.get("nodes")) : 0;
        int graphEdges = graphData != null ? getCollectionSize(graphData.get("edges")) : 0;

        pushPreviewSymbols.clear();
        pushPreviewSymbols.addAll(symbols);
        pushPreviewDocuments.clear();
        pushPreviewDocuments.addAll(documents);
        pushPreviewGraphData = graphData;
        symGraphTab.setPushPreview(symbols, graphData, graphNodes, graphEdges, documents);

        List<String> parts = new ArrayList<>();
        parts.add(symbols.size() + " symbols ready");
        parts.add(documents.size() + " documents ready");
        if (graphData != null) {
            parts.add(graphNodes + " nodes");
            parts.add(graphEdges + " edges");
        }
        symGraphTab.setPushStatus("Preview ready: " + String.join(", ", parts), true);
    }

    public void handlePush(String scope, Boolean pushSymbols, Boolean pushGraph, String visibility) {
        if (symGraphTab == null || symGraphService == null) {
            Msg.showError(this, null, "Error", "SymGraph tab not initialized");
            return;
        }

        String sha256 = getProgramSHA256();
        if (sha256 == null) {
            Msg.showInfo(this, symGraphTab, "No Binary", "No binary loaded or unable to compute hash.");
            return;
        }

        if (!symGraphService.hasApiKey()) {
            Msg.showError(this, symGraphTab, "API Key Required",
                "Push requires a SymGraph API key.\n\nAdd your API key in Settings > General > SymGraph");
            return;
        }

        SymGraphTab.PushConfig pushConfig = symGraphTab.getPushConfig();
        String resolvedScope = scope != null ? scope : pushConfig.getScope();
        String resolvedVisibility = visibility != null ? visibility : pushConfig.getVisibility();
        boolean useGraph = pushGraph != null ? pushGraph : pushConfig.isPushGraph();
        List<Map<String, Object>> selectedSymbols = symGraphTab.getSelectedPushSymbols();
        List<Map<String, Object>> selectedDocuments = symGraphTab.getSelectedPushDocuments();
        Map<String, Object> graphData = useGraph ? pushPreviewGraphData : null;

        if (selectedSymbols.isEmpty() && selectedDocuments.isEmpty() && graphData == null) {
            symGraphTab.setPushStatus("Preview the push and select at least one row first", false);
            return;
        }

        pendingPushScope = resolvedScope;
        pendingPushSymbols = pushSymbols != null ? pushSymbols : !selectedSymbols.isEmpty();
        pendingPushGraph = graphData != null;
        pendingPushVisibility = resolvedVisibility;
        pendingPushDocuments = new ArrayList<>(selectedDocuments);

        // Use atomic boolean for cancellation
        final java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean(false);

        // Show progress bar with cancel callback
        symGraphTab.setPushStatus("Preparing...", null);
        symGraphTab.showPushProgress(() -> cancelled.set(true));

        // Create progress callback that updates the UI
        SymGraphService.ProgressCallback progressCallback = new SymGraphService.ProgressCallback() {
            @Override
            public void onProgress(int current, int total, String message) {
                SwingUtilities.invokeLater(() -> {
                    symGraphTab.updatePushProgress(current, total, message);
                });
            }

            @Override
            public boolean isCancelled() {
                return cancelled.get();
            }
        };

        // Run in background thread (no modal dialog)
        final List<Map<String, Object>> symbolsToPush = new ArrayList<>(selectedSymbols);
        final List<Map<String, Object>> documentsToPush = new ArrayList<>(selectedDocuments);
        final Map<String, Object> graphDataToPush = graphData;
        final String visibilityForPush = resolvedVisibility;
        Thread pushThread = new Thread(() -> {
            try {
                // Build PLT/thunk address map up front so it's available for both symbol and graph collection
                externalAddressMap = buildExternalAddressMap();

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                if (symbolsToPush.isEmpty() && documentsToPush.isEmpty() && graphDataToPush == null) {
                    SwingUtilities.invokeLater(() -> {
                        symGraphTab.hidePushProgress();
                        symGraphTab.setButtonsEnabled(true);
                        symGraphTab.setPushStatus("No data to push", false);
                    });
                    return;
                }

                PushResult totalResult = PushResult.success(0, 0, 0);
                PushResult revisionResult = symGraphService.createBinaryRevision(sha256, visibilityForPush);
                if (!revisionResult.isSuccess()) {
                    final PushResult failureResult = revisionResult;
                    SwingUtilities.invokeLater(() -> handlePushFailure(failureResult));
                    return;
                }
                Integer targetRevision = revisionResult.getBinaryRevision();
                totalResult.setBinaryRevision(targetRevision);

                // Push symbols in chunks with progress
                if (!symbolsToPush.isEmpty()) {
                    PushResult symbolResult = symGraphService.pushSymbolsChunked(
                        sha256, symbolsToPush, targetRevision, progressCallback);
                    if (!symbolResult.isSuccess()) {
                        final PushResult failureResult = symbolResult;
                        SwingUtilities.invokeLater(() -> handlePushFailure(failureResult));
                        return;
                    }
                    totalResult.setSymbolsPushed(symbolResult.getSymbolsPushed());
                }

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                // Push graph in chunks with progress
                if (graphDataToPush != null) {
                    PushResult graphResult = symGraphService.importGraphChunked(
                        sha256, graphDataToPush, targetRevision, progressCallback);
                    if (!graphResult.isSuccess()) {
                        final PushResult failureResult = graphResult;
                        SwingUtilities.invokeLater(() -> handlePushFailure(failureResult));
                        return;
                    }
                    totalResult.setNodesPushed(graphResult.getNodesPushed());
                    totalResult.setEdgesPushed(graphResult.getEdgesPushed());
                }

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                if (!documentsToPush.isEmpty()) {
                    SwingUtilities.invokeLater(() -> symGraphTab.updatePushProgress(100, 100, "Pushing documents..."));
                    PushResult documentResult = symGraphService.pushDocumentsBulk(
                            sha256, documentsToPush, targetRevision, progressCallback);
                    if (!documentResult.isSuccess()) {
                        final PushResult failureResult = documentResult;
                        SwingUtilities.invokeLater(() -> handlePushFailure(failureResult));
                        return;
                    }
                    totalResult.setDocumentsPushed(documentResult.getDocumentsPushed());
                    totalResult.setDocumentResults(documentResult.getDocumentResults());
                    if (queryService != null) {
                        updateLocalDocumentMetadata(documentsToPush, documentResult.getDocumentResults());
                    }
                }

                if (cancelled.get()) {
                    handlePushCancelled();
                    return;
                }

                // Add fingerprints for debug symbol matching (BuildID for ELF, etc.)
                SwingUtilities.invokeLater(() -> symGraphTab.updatePushProgress(100, 100, "Adding fingerprints..."));
                addBinaryFingerprints(sha256);

                final PushResult result = totalResult;
                SwingUtilities.invokeLater(() -> {
                    symGraphTab.hidePushProgress();
                    symGraphTab.setButtonsEnabled(true);
                    StringBuilder msg = new StringBuilder("Pushed: ");
                    List<String> parts = new ArrayList<>();
                    if (result.getSymbolsPushed() > 0) parts.add(result.getSymbolsPushed() + " symbols");
                    if (result.getNodesPushed() > 0) parts.add(result.getNodesPushed() + " nodes");
                    if (result.getEdgesPushed() > 0) parts.add(result.getEdgesPushed() + " edges");
                    if (result.getDocumentsPushed() > 0) parts.add(result.getDocumentsPushed() + " documents");
                    msg.append(parts.isEmpty() ? "complete" : String.join(", ", parts));
                    if (result.getBinaryRevision() != null) {
                        if (result.getDocumentsPushed() > 0) {
                            msg.append(" from v").append(result.getBinaryRevision())
                                    .append(" (documents versioned separately)");
                        } else {
                            msg.append(" to v").append(result.getBinaryRevision());
                        }
                    }
                    pendingPushDocuments = new ArrayList<>();
                    symGraphTab.setPushStatus(msg.toString(), true);
                });
            } catch (Exception e) {
                Msg.error(this, "Push error: " + e.getMessage(), e);
                SwingUtilities.invokeLater(() -> {
                    symGraphTab.hidePushProgress();
                    symGraphTab.setButtonsEnabled(true);
                    symGraphTab.setPushStatus("Error: " + e.getMessage(), false);
                    pendingPushDocuments = new ArrayList<>();
                });
            }
        }, "SymGraph-Push-Worker");
        pushThread.setDaemon(true);
        pushThread.start();
    }

    private void handlePushFailure(PushResult failureResult) {
        symGraphTab.hidePushProgress();
        symGraphTab.setButtonsEnabled(true);
        pendingPushDocuments = new ArrayList<>();

        if ("visibility_quota_exceeded".equals(failureResult.getErrorCode())
                && failureResult.getRequestedVisibility() != null
                && !"public".equals(failureResult.getRequestedVisibility())) {
            String suggestedVisibility = failureResult.getSuggestedVisibility() != null
                    ? failureResult.getSuggestedVisibility()
                    : "public";
            int choice = JOptionPane.showConfirmDialog(
                    symGraphTab,
                    failureResult.getError() + "\n\nRetry this push as " + suggestedVisibility + "?",
                    "Visibility Not Available",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (choice == JOptionPane.YES_OPTION) {
                handlePush(pendingPushScope, pendingPushSymbols, pendingPushGraph, suggestedVisibility);
                return;
            }
        }

        symGraphTab.setPushStatus("Error: " + failureResult.getError(), false);
    }

    private void handlePushCancelled() {
        SwingUtilities.invokeLater(() -> {
            symGraphTab.hidePushProgress();
            symGraphTab.setButtonsEnabled(true);
            pendingPushDocuments = new ArrayList<>();
            symGraphTab.setPushStatus("Cancelled", false);
        });
    }

    // ==== Pull Operations ====

    /**
     * Handle SymGraph pull preview request.
     */
    public void handlePullPreview() {
        if (symGraphTab == null || symGraphService == null) {
            Msg.showError(this, null, "Error", "SymGraph tab not initialized");
            return;
        }

        // If a worker is already running, cancel it
        if (pullWorker != null && !pullWorker.isDone()) {
            pullWorker.requestCancel();
            return;
        }

        String sha256 = getProgramSHA256();
        if (sha256 == null) {
            Msg.showInfo(this, symGraphTab, "No Binary", "No binary loaded or unable to compute hash.");
            return;
        }

        if (!symGraphService.hasApiKey()) {
            Msg.showError(this, symGraphTab, "API Key Required",
                "Pull requires a SymGraph API key.\n\nAdd your API key in Settings > General > SymGraph");
            return;
        }

        // Get pull configuration from the tab
        SymGraphTab.PullConfig pullConfig = symGraphTab.getPullConfig();
        List<String> symbolTypes = pullConfig.getSymbolTypes();
        double minConfidence = pullConfig.getMinConfidence();
        boolean includeGraph = pullConfig.isIncludeGraph();
        Integer version = pullConfig.getVersion();
        String nameFilter = pullConfig.getNameFilter();

        if (symbolTypes.isEmpty() && !includeGraph) {
            Msg.info(this, "Fetching documents-only preview from SymGraph: " + sha256);
        } else if (symbolTypes.isEmpty()) {
            Msg.info(this, "Fetching graph/documents preview from SymGraph: " + sha256);
        } else {
            Msg.info(this, "Fetching symbols from SymGraph: " + sha256 + " (types: " + symbolTypes + ")");
        }
        symGraphTab.clearConflicts();
        symGraphTab.setGraphPreviewData(null, 0, 0, 0);
        symGraphTab.setButtonsEnabled(false);

        pullWorker = new SymGraphPullWorker(
            plugin.getCurrentProgram(),
            symGraphService,
            sha256,
            symbolTypes,
            minConfidence,
            includeGraph,
            version,
            nameFilter
        );

        setupPullWorkerCallbacks(pullWorker);
        pullWorker.execute();
    }

    /**
     * Set up callbacks for the pull worker.
     */
    private void setupPullWorkerCallbacks(SymGraphPullWorker worker) {
        // Progress callback - called on EDT
        worker.setProgressCallback(progress -> {
            symGraphTab.updatePullProgress(progress.current, 100, progress.message);
        });

        // Completed callback - called on EDT
        worker.setCompletedCallback(result -> {
            symGraphTab.hidePullProgress();
            symGraphTab.setButtonsEnabled(true);

            if (result.cancelled) {
                symGraphTab.setPullStatus("Cancelled", false);
            } else if (result.error != null) {
                symGraphTab.setGraphPreviewData(null, 0, 0, 0);
                symGraphTab.populateFetchDocuments(new ArrayList<>());
                symGraphTab.setPullStatus("Error: " + result.error, false);
            } else {
                symGraphTab.setGraphPreviewData(result.graphExport, result.graphNodes,
                    result.graphEdges, result.graphCommunities);
                symGraphTab.populateConflicts(result.conflicts);
                symGraphTab.populateFetchDocuments(result.documents);

                int conflictCount = (int) result.conflicts.stream()
                    .filter(c -> c.getAction() == ConflictAction.CONFLICT).count();
                int newCount = (int) result.conflicts.stream()
                    .filter(c -> c.getAction() == ConflictAction.NEW).count();
                String status;
                if (result.conflicts.isEmpty() && result.graphExport == null && result.documents.isEmpty()) {
                    status = "No symbols or documents found";
                } else if (result.conflicts.isEmpty() && result.graphExport != null) {
                    status = "No symbols found (graph data available)";
                } else if (result.conflicts.isEmpty()) {
                    status = "No symbols found";
                } else {
                    status = String.format("Found %d symbols (%d conflicts, %d new)",
                            result.conflicts.size(), conflictCount, newCount);
                }
                if (result.conflicts.isEmpty() && result.graphExport != null) {
                    status = "No symbols found (graph data available)";
                } else if (result.graphExport != null) {
                    status += String.format(" | Graph: %d nodes, %d edges, %d communities",
                        result.graphNodes, result.graphEdges, result.graphCommunities);
                }
                if (!result.documents.isEmpty()) {
                    status += String.format(" | Documents: %d", result.documents.size());
                }
                symGraphTab.setPullStatus(status, true);
            }
        });

        // Cancelled callback - called on EDT
        worker.setCancelledCallback(() -> {
            symGraphTab.hidePullProgress();
            symGraphTab.setButtonsEnabled(true);
            symGraphTab.setPullStatus("Cancelled", false);
        });

        // Failed callback - called on EDT
        worker.setFailedCallback(error -> {
            symGraphTab.hidePullProgress();
            symGraphTab.setButtonsEnabled(true);
            symGraphTab.setGraphPreviewData(null, 0, 0, 0);
            symGraphTab.populateFetchDocuments(new ArrayList<>());
            symGraphTab.setPullStatus("Error: " + error, false);
        });

        // Show progress
        symGraphTab.showPullProgress("Fetching...");
    }

    /**
     * Cancel the current pull operation if running.
     */
    public void cancelPull() {
        if (pullWorker != null && !pullWorker.isDone()) {
            pullWorker.requestCancel();
        }
    }

    // ==== Apply Operations ====

    /**
     * Handle applying selected symbols from SymGraph.
     */
    public void handleApplySelected(List<ConflictEntry> selectedConflicts) {
        if (symGraphTab == null || plugin.getCurrentProgram() == null) {
            return;
        }

        // If a worker is already running, cancel it
        if (applyWorker != null && !applyWorker.isDone()) {
            applyWorker.requestCancel();
            return;
        }

        GraphExport graphExport = symGraphTab.getGraphPreviewData();
        List<DocumentSummary> selectedDocuments = symGraphTab.getSelectedFetchDocuments();
        if (selectedConflicts.isEmpty() && selectedDocuments.isEmpty() && graphExport == null) {
            symGraphTab.setPullStatus("No items selected", false);
            return;
        }

        String programHash = getProgramSHA256();
        if (graphExport != null && programHash == null) {
            symGraphTab.setPullStatus("Unable to resolve program hash", false);
            return;
        }

        if (selectedConflicts.isEmpty() && graphExport == null) {
            startDocumentApply(selectedDocuments, null);
            return;
        }

        pendingApplyDocuments = new ArrayList<>(selectedDocuments);
        pendingApplyBaseMessage = null;

        applyWorker = new SymGraphApplyWorker(
            plugin.getCurrentProgram(),
            analysisDB,
            selectedConflicts,
            graphExport,
            programHash,
            symGraphTab.getGraphMergePolicy()
        );

        setupApplyWorkerCallbacks(applyWorker, selectedConflicts.size());
        applyWorker.execute();
    }

    /**
     * Handle applying all NEW symbols from SymGraph (wizard shortcut).
     */
    public void handleApplyAllNew() {
        if (symGraphTab == null || plugin.getCurrentProgram() == null) {
            return;
        }

        // If a worker is already running, cancel it
        if (applyWorker != null && !applyWorker.isDone()) {
            applyWorker.requestCancel();
            return;
        }

        List<ConflictEntry> newConflicts = symGraphTab.getAllNewConflicts();
        GraphExport graphExport = symGraphTab.getGraphPreviewData();
        if (newConflicts.isEmpty() && graphExport == null) {
            symGraphTab.setPullStatus("No new symbols to apply", false);
            return;
        }

        String programHash = getProgramSHA256();
        if (graphExport != null && programHash == null) {
            symGraphTab.setPullStatus("Unable to resolve program hash", false);
            return;
        }

        applyWorker = new SymGraphApplyWorker(
            plugin.getCurrentProgram(),
            analysisDB,
            newConflicts,
            graphExport,
            programHash,
            symGraphTab.getGraphMergePolicy()
        );

        pendingApplyDocuments = new ArrayList<>();
        pendingApplyBaseMessage = null;
        setupApplyWorkerCallbacks(applyWorker, newConflicts.size());
        applyWorker.execute();
    }

    /**
     * Set up callbacks for the apply worker.
     */
    private void setupApplyWorkerCallbacks(SymGraphApplyWorker worker, int totalSymbols) {
        // Progress callback - called on EDT
        worker.setProgressCallback(progress -> {
            symGraphTab.updateApplyProgress(progress.current, 100, progress.message);
        });

        // Completed callback - called on EDT
        worker.setCompletedCallback(result -> {
            symGraphTab.hideApplyProgress();
            if (result.cancelled) {
                pendingApplyDocuments = new ArrayList<>();
                pendingApplyBaseMessage = null;
                symGraphTab.showCompletePage(
                    String.format("Cancelled after applying %d symbols", result.symbolsApplied), false);
            } else if (result.error != null) {
                pendingApplyDocuments = new ArrayList<>();
                pendingApplyBaseMessage = null;
                symGraphTab.showCompletePage("Error: " + result.error, false);
            } else {
                StringBuilder message = new StringBuilder("Applied ");
                List<String> parts = new ArrayList<>();
                if (result.symbolsApplied > 0) {
                    parts.add(result.symbolsApplied + " symbols");
                }
                if (result.nodesApplied > 0) {
                    parts.add(result.nodesApplied + " nodes");
                }
                if (result.edgesApplied > 0) {
                    parts.add(result.edgesApplied + " edges");
                }
                if (parts.isEmpty()) {
                    message.append("no changes");
                } else {
                    message.append(String.join(", ", parts));
                }
                if (!pendingApplyDocuments.isEmpty()) {
                    pendingApplyBaseMessage = message.toString();
                    startDocumentApply(new ArrayList<>(pendingApplyDocuments), pendingApplyBaseMessage);
                } else {
                    pendingApplyBaseMessage = null;
                    symGraphTab.showCompletePage(message.toString(), true);
                }
            }
        });

        // Cancelled callback - called on EDT
        worker.setCancelledCallback(() -> {
            symGraphTab.hideApplyProgress();
            pendingApplyDocuments = new ArrayList<>();
            pendingApplyBaseMessage = null;
            symGraphTab.showCompletePage("Apply cancelled", false);
        });

        // Failed callback - called on EDT
        worker.setFailedCallback(error -> {
            symGraphTab.hideApplyProgress();
            pendingApplyDocuments = new ArrayList<>();
            pendingApplyBaseMessage = null;
            symGraphTab.showCompletePage("Error: " + error, false);
        });

        // Show the applying page with progress
        String message = totalSymbols > 0 ?
            String.format("Applying %d symbols...", totalSymbols) :
            "Applying graph data...";
        symGraphTab.showApplyingPage(message);
    }

    /**
     * Cancel the current apply operation if running.
     */
    public void cancelApply() {
        if (applyWorker != null && !applyWorker.isDone()) {
            applyWorker.requestCancel();
        }
    }

    private void startDocumentApply(List<DocumentSummary> documents, String baseMessage) {
        if (documents == null || documents.isEmpty()) {
            if (baseMessage != null) {
                symGraphTab.showCompletePage(baseMessage, true);
            }
            pendingApplyDocuments = new ArrayList<>();
            pendingApplyBaseMessage = null;
            return;
        }

        String sha256 = getProgramSHA256();
        if (sha256 == null || queryService == null) {
            symGraphTab.showCompletePage("Unable to import documents", false);
            pendingApplyDocuments = new ArrayList<>();
            pendingApplyBaseMessage = null;
            return;
        }

        symGraphTab.showApplyingPage(String.format("Fetching %d documents...", documents.size()));
        pendingApplyDocuments = new ArrayList<>(documents);
        pendingApplyBaseMessage = baseMessage;

        Thread documentThread = new Thread(() -> {
            int imported = 0;
            int failures = 0;
            String lastError = null;

            for (DocumentSummary summary : documents) {
                try {
                    Document document = symGraphService.getDocument(
                            sha256, summary.getDocumentIdentityId(), summary.getVersion());
                    if (document != null && queryService.upsertSymGraphDocumentChat(document) != -1) {
                        imported++;
                    } else {
                        failures++;
                    }
                } catch (Exception e) {
                    failures++;
                    lastError = e.getMessage();
                    Msg.warn(this, "Failed to fetch document " + summary.getDocumentIdentityId() + ": " + e.getMessage());
                }
            }

            final int importedCount = imported;
            final int failureCount = failures;
            final String errorMessage = lastError;
            SwingUtilities.invokeLater(() -> {
                if (refreshChatHistoryCallback != null && importedCount > 0) {
                    refreshChatHistoryCallback.run();
                }
                List<String> parts = new ArrayList<>();
                if (baseMessage != null && !baseMessage.isEmpty() && !"Applied no changes".equals(baseMessage)) {
                    parts.add(baseMessage);
                }
                if (importedCount > 0) {
                    parts.add("Applied " + importedCount + " documents");
                } else if (baseMessage == null) {
                    parts.add("No documents applied");
                }
                if (failureCount > 0) {
                    parts.add(failureCount + " document fetch failures");
                }
                pendingApplyDocuments = new ArrayList<>();
                pendingApplyBaseMessage = null;
                symGraphTab.showCompletePage(String.join(" | ", parts), failureCount == 0 || importedCount > 0);
                if (failureCount > 0 && importedCount == 0 && errorMessage != null) {
                    symGraphTab.setPullStatus("Error: " + errorMessage, false);
                }
            });
        }, "SymGraph-Document-Apply");
        documentThread.setDaemon(true);
        documentThread.start();
    }

    private void updateLocalDocumentMetadata(
            List<Map<String, Object>> selectedDocuments,
            List<DocumentPushResult> results) {
        if (queryService == null || selectedDocuments == null || results == null) {
            return;
        }

        int count = Math.min(selectedDocuments.size(), results.size());
        for (int i = 0; i < count; i++) {
            Map<String, Object> localDocument = selectedDocuments.get(i);
            DocumentPushResult result = results.get(i);
            Object sessionId = localDocument.get("session_id");
            if (!(sessionId instanceof Number)) {
                continue;
            }

            String docType = result.getDocument() != null && result.getDocument().getDocType() != null
                    ? result.getDocument().getDocType()
                    : valueAsString(localDocument.get("doc_type"));
            String documentIdentityId = result.getDocument() != null && result.getDocument().getDocumentIdentityId() != null
                    ? result.getDocument().getDocumentIdentityId()
                    : result.getDocumentIdentityId();
            Integer version = result.getDocument() != null
                    ? result.getDocument().getVersion()
                    : result.getVersion();

            queryService.updateDocumentSyncMetadata(
                    ((Number) sessionId).intValue(),
                    documentIdentityId,
                    version,
                    docType);
        }
    }

    // ==== Binary Info ====

    /**
     * Update SymGraph tab binary info when program changes.
     */
    public void updateBinaryInfo() {
        if (symGraphTab == null) {
            return;
        }

        if (plugin.getCurrentProgram() != null) {
            String name = plugin.getCurrentProgram().getName();
            String sha256 = getProgramSHA256();
            symGraphTab.setBinaryInfo(name, sha256, buildLocalSummary(sha256));
        } else {
            symGraphTab.setBinaryInfo(null, null);
        }
    }

    private boolean matchesPushTypeFilter(Map<String, Object> symbol, List<String> selectedTypes) {
        Object symbolTypeValue = symbol.get("symbol_type");
        if (!(symbolTypeValue instanceof String)) {
            return false;
        }
        String symbolType = ((String) symbolTypeValue).toLowerCase();
        if (selectedTypes.contains(symbolType)) {
            return true;
        }
        return "type".equals(symbolType) || "enum".equals(symbolType) || "struct".equals(symbolType)
                ? selectedTypes.contains("type")
                : false;
    }

    private boolean matchesNameFilter(Map<String, Object> symbol, String nameFilter) {
        Object name = symbol.get("name");
        if (name instanceof String && ((String) name).toLowerCase().contains(nameFilter)) {
            return true;
        }
        Object content = symbol.get("content");
        return content instanceof String && ((String) content).toLowerCase().contains(nameFilter);
    }

    private int getCollectionSize(Object value) {
        if (value instanceof List) {
            return ((List<?>) value).size();
        }
        return 0;
    }

    private String valueAsString(Object value) {
        return value != null ? value.toString() : null;
    }

    private String buildLocalSummary(String sha256) {
        if (plugin.getCurrentProgram() == null) {
            return "No binary loaded";
        }

        List<String> parts = new ArrayList<>();
        try {
            int functionCount = plugin.getCurrentProgram().getFunctionManager().getFunctionCount();
            parts.add(String.format("%,d functions", functionCount));
        } catch (Exception ignored) {
        }

        if (sha256 != null && analysisDB != null) {
            try {
                BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(sha256);
                if (graph != null && graph.getNodeCount() > 0) {
                    parts.add(String.format("%,d graph nodes", graph.getNodeCount()));
                    parts.add(String.format("%,d graph edges", graph.getEdgeCount()));
                }
            } catch (Exception ignored) {
            }
        }

        return parts.isEmpty() ? "Binary metadata available" : String.join(" | ", parts);
    }

    // ==== Helper Methods ====

    /**
     * Determine symbol provenance: decompiler (auto-named), llm (LLM-renamed), or user (manually renamed).
     */
    private String getSymbolProvenance(boolean isAutoName, long address, String symbolType) {
        if (isAutoName) {
            return "decompiler";
        }
        try {
            String programHash = getProgramSHA256();
            if (programHash != null && analysisDB != null && analysisDB.isLlmRenamed(programHash, address, symbolType)) {
                return "llm";
            }
        } catch (Exception e) {
            // Fall through to "user"
        }
        return "user";
    }

    private String getProgramSHA256() {
        try {
            if (plugin.getCurrentProgram() != null) {
                return plugin.getCurrentProgram().getExecutableSHA256();
            }
        } catch (Exception e) {
            Msg.error(this, "Error getting SHA256: " + e.getMessage());
        }
        return null;
    }

    /**
     * Add fingerprints to the binary for debug symbol matching.
     * Extracts BuildID (for ELF) or other identifiers and adds them as fingerprints.
     */
    private void addBinaryFingerprints(String sha256) {
        if (plugin.getCurrentProgram() == null || symGraphService == null) {
            return;
        }

        Program program = plugin.getCurrentProgram();

        try {
            // Check executable format
            String format = program.getExecutableFormat();

            if ("Executable and Linking Format (ELF)".equals(format) ||
                (format != null && format.contains("ELF"))) {
                // Extract BuildID from ELF
                String buildId = extractElfBuildId(program);
                if (buildId != null && !buildId.isEmpty()) {
                    Msg.info(this, "Extracted ELF BuildID: " + buildId);
                    try {
                        symGraphService.addFingerprint(sha256, "build_id", buildId);
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to add BuildID fingerprint: " + e.getMessage());
                    }
                }
            }
            // PE/PDB GUID extraction would go here if needed

        } catch (Exception e) {
            Msg.warn(this, "Error extracting fingerprints: " + e.getMessage());
        }
    }

    /**
     * Extract GNU BuildID from an ELF binary.
     */
    private String extractElfBuildId(Program program) {
        try {
            // Look for .note.gnu.build-id section
            ghidra.program.model.mem.MemoryBlock buildIdBlock = null;
            for (ghidra.program.model.mem.MemoryBlock block : program.getMemory().getBlocks()) {
                if (".note.gnu.build-id".equals(block.getName())) {
                    buildIdBlock = block;
                    break;
                }
            }

            if (buildIdBlock == null) {
                // Try alternative names
                for (ghidra.program.model.mem.MemoryBlock block : program.getMemory().getBlocks()) {
                    String name = block.getName();
                    if (name != null && name.contains("build") && name.contains("id")) {
                        buildIdBlock = block;
                        break;
                    }
                }
            }

            if (buildIdBlock != null) {
                // Read the note section
                int size = (int) buildIdBlock.getSize();
                if (size > 256) size = 256; // Sanity limit

                byte[] data = new byte[size];
                buildIdBlock.getBytes(buildIdBlock.getStart(), data);

                if (data.length >= 16) {
                    // GNU note format: namesz (4), descsz (4), type (4), name, desc
                    int namesz = readLittleEndianInt(data, 0);
                    int descsz = readLittleEndianInt(data, 4);
                    int noteType = readLittleEndianInt(data, 8);

                    if (noteType == 3) { // NT_GNU_BUILD_ID
                        // Name is padded to 4-byte boundary
                        int nameEnd = 12 + ((namesz + 3) & ~3);
                        if (data.length >= nameEnd + descsz) {
                            StringBuilder sb = new StringBuilder();
                            for (int i = nameEnd; i < nameEnd + descsz; i++) {
                                sb.append(String.format("%02x", data[i] & 0xff));
                            }
                            return sb.toString();
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Error extracting ELF BuildID: " + e.getMessage());
        }
        return null;
    }

    private int readLittleEndianInt(byte[] data, int offset) {
        return (data[offset] & 0xff) |
               ((data[offset + 1] & 0xff) << 8) |
               ((data[offset + 2] & 0xff) << 16) |
               ((data[offset + 3] & 0xff) << 24);
    }

    private List<Map<String, Object>> collectLocalSymbols(String scope) {
        List<Map<String, Object>> symbols = new ArrayList<>();

        if (plugin.getCurrentProgram() == null) {
            return symbols;
        }

        Program program = plugin.getCurrentProgram();

        try {
            if ("function".equals(scope)) {
                Function currentFunc = plugin.getCurrentFunction();
                if (currentFunc != null) {
                    symbols.add(functionToSymbolMap(currentFunc));
                    // Collect function comments and local variables
                    symbols.addAll(collectFunctionComments(currentFunc));
                    symbols.addAll(collectFunctionVariables(currentFunc));
                }
            } else {
                // Full binary - all symbol types

                // 1. Functions
                for (Function func : program.getFunctionManager().getFunctions(true)) {
                    symbols.add(functionToSymbolMap(func));
                }

                // 2. Data (global variables)
                symbols.addAll(collectDataSymbols(program));

                // 3. Types and enums
                symbols.addAll(collectTypesAndEnums(program));

                // 4. Comments
                symbols.addAll(collectAllComments(program));
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting symbols: " + e.getMessage());
        }

        return symbols;
    }

    private Map<String, Object> functionToSymbolMap(Function func) {
        Map<String, Object> map = new HashMap<>();
        map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
        map.put("symbol_type", "function");
        map.put("name", getQualifiedFunctionName(func));
        // Include function signature as data_type
        if (func.getSignature() != null) {
            map.put("data_type", func.getSignature().getPrototypeString());
        }
        // Use unified default name detection for cross-tool compatibility
        boolean isAuto = ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(func.getName());
        map.put("confidence", isAuto ? 0.5 : 0.9);
        map.put("provenance", getSymbolProvenance(isAuto, func.getEntryPoint().getOffset(), "function"));
        return map;
    }

    private List<Map<String, Object>> collectDataSymbols(Program program) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        try {
            ghidra.program.model.listing.Listing listing = program.getListing();
            ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);

            while (dataIter.hasNext()) {
                ghidra.program.model.listing.Data data = dataIter.next();
                if (data != null) {
                    ghidra.program.model.address.Address addr = data.getAddress();
                    ghidra.program.model.symbol.Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
                    String name = (sym != null) ? sym.getName() : null;

                    // Skip variables without names
                    if (name == null || name.isEmpty()) {
                        continue;
                    }

                    // Use unified default name detection for cross-tool compatibility
                    boolean isAutoNamed = ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(name);

                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", addr.getOffset()));
                    map.put("symbol_type", "variable");
                    map.put("name", name);
                    if (data.getDataType() != null) {
                        map.put("data_type", data.getDataType().getName());
                    }
                    map.put("confidence", isAutoNamed ? 0.3 : 0.85);
                    map.put("provenance", getSymbolProvenance(isAutoNamed, addr.getOffset(), "variable"));
                    symbols.add(map);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting data symbols: " + e.getMessage());
        }
        return symbols;
    }

    private List<Map<String, Object>> collectFunctionVariables(Function func) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        try {
            // Parameters - use ordinal for index
            ghidra.program.model.listing.Parameter[] params = func.getParameters();
            for (int i = 0; i < params.length; i++) {
                ghidra.program.model.listing.Parameter param = params[i];
                if (param.getName() != null) {
                    // Use unified default name detection for cross-tool compatibility
                    boolean isAuto = ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(param.getName());
                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                    map.put("symbol_type", "variable");
                    map.put("name", param.getName());
                    if (param.getDataType() != null) {
                        map.put("data_type", param.getDataType().getName());
                    }
                    map.put("confidence", isAuto ? 0.3 : 0.8);
                    map.put("provenance", getSymbolProvenance(isAuto, func.getEntryPoint().getOffset(), "variable"));

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("scope", "parameter");
                    metadata.put("function", getQualifiedFunctionName(func));
                    metadata.put("storage_class", "parameter");
                    metadata.put("parameter_index", param.getOrdinal());

                    // Also capture actual storage location
                    try {
                        if (param.isRegisterVariable()) {
                            ghidra.program.model.lang.Register reg = param.getRegister();
                            if (reg != null) {
                                metadata.put("register", reg.getName());
                            }
                        } else if (param.isStackVariable()) {
                            metadata.put("stack_offset", param.getStackOffset());
                        }
                    } catch (Exception e) {
                        // Storage info optional
                    }

                    map.put("metadata", metadata);
                    symbols.add(map);
                }
            }

            // Local variables
            for (ghidra.program.model.listing.Variable var : func.getLocalVariables()) {
                if (var.getName() != null) {
                    // Use unified default name detection for cross-tool compatibility
                    boolean isAuto = ghidrassist.services.symgraph.SymGraphUtils.isDefaultName(var.getName());
                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                    map.put("symbol_type", "variable");
                    map.put("name", var.getName());
                    if (var.getDataType() != null) {
                        map.put("data_type", var.getDataType().getName());
                    }
                    map.put("confidence", isAuto ? 0.3 : 0.75);
                    map.put("provenance", getSymbolProvenance(isAuto, func.getEntryPoint().getOffset(), "variable"));

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("scope", "local");
                    metadata.put("function", getQualifiedFunctionName(func));

                    try {
                        if (var.isStackVariable()) {
                            metadata.put("storage_class", "stack");
                            metadata.put("stack_offset", var.getStackOffset());
                        } else if (var.isRegisterVariable()) {
                            metadata.put("storage_class", "register");
                            ghidra.program.model.lang.Register reg = var.getRegister();
                            if (reg != null) {
                                metadata.put("register", reg.getName());
                            }
                        } else {
                            metadata.put("storage_class", "compound");
                            metadata.put("storage_string", var.getVariableStorage().toString());
                        }
                    } catch (UnsupportedOperationException e) {
                        metadata.put("storage_class", "compound");
                        metadata.put("storage_string", var.getVariableStorage().toString());
                    }

                    map.put("metadata", metadata);
                    symbols.add(map);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting function variables: " + e.getMessage());
        }
        return symbols;
    }

    private List<Map<String, Object>> collectTypesAndEnums(Program program) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        try {
            ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();

            // Iterate through all user-defined types
            java.util.Iterator<ghidra.program.model.data.DataType> iter = dtm.getAllDataTypes();
            while (iter.hasNext()) {
                ghidra.program.model.data.DataType dt = iter.next();
                // Skip built-in types (only collect user-defined)
                ghidra.program.model.data.SourceArchive srcArchive = dt.getSourceArchive();
                if (srcArchive == null) {
                    continue;
                }
                // Skip types from built-in archives
                if (srcArchive.getArchiveType() == ghidra.program.model.data.ArchiveType.BUILT_IN) {
                    continue;
                }

                Map<String, Object> map = new HashMap<>();
                map.put("address", "0x0"); // Types don't have addresses
                map.put("name", dt.getName());
                map.put("data_type", dt.getDisplayName());
                map.put("confidence", 0.9);
                map.put("provenance", "user");

                if (dt instanceof ghidra.program.model.data.Enum) {
                    ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
                    map.put("symbol_type", "enum");
                    // Collect enum members
                    Map<String, Object> metadata = new HashMap<>();
                    Map<String, Long> members = new HashMap<>();
                    StringBuilder contentBuilder = new StringBuilder();
                    contentBuilder.append("enum ").append(dt.getName()).append(" {\n");
                    for (String name : enumType.getNames()) {
                        long value = enumType.getValue(name);
                        members.put(name, value);
                        contentBuilder.append(String.format("    %s = 0x%x,\n", name, value));
                    }
                    contentBuilder.append("}");
                    metadata.put("members", members);
                    map.put("metadata", metadata);
                    map.put("content", contentBuilder.toString());
                    map.put("data_type", contentBuilder.toString());
                } else if (dt instanceof ghidra.program.model.data.Structure) {
                    ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) dt;
                    map.put("symbol_type", "struct");
                    // Collect struct fields
                    List<Map<String, Object>> fields = new ArrayList<>();
                    StringBuilder contentBuilder = new StringBuilder();
                    contentBuilder.append("struct ").append(dt.getName()).append(" {\n");
                    for (ghidra.program.model.data.DataTypeComponent comp : struct.getComponents()) {
                        Map<String, Object> field = new HashMap<>();
                        String fieldName = comp.getFieldName();
                        String fieldType = comp.getDataType().getName();
                        int offset = comp.getOffset();
                        field.put("name", fieldName);
                        field.put("type", fieldType);
                        field.put("offset", offset);
                        fields.add(field);
                        contentBuilder.append(String.format("    /* 0x%02x */ %s %s;\n",
                            offset, fieldType, fieldName != null ? fieldName : "field_" + offset));
                    }
                    contentBuilder.append("}");
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("fields", fields);
                    map.put("metadata", metadata);
                    map.put("content", contentBuilder.toString());
                    map.put("data_type", contentBuilder.toString());
                } else {
                    map.put("symbol_type", "type");
                }

                symbols.add(map);
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting types and enums: " + e.getMessage());
        }
        return symbols;
    }

    private List<Map<String, Object>> collectAllComments(Program program) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        try {
            // Collect function-level and address comments
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                symbols.addAll(collectFunctionComments(func));
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting comments: " + e.getMessage());
        }
        return symbols;
    }

    private List<Map<String, Object>> collectFunctionComments(Function func) {
        List<Map<String, Object>> symbols = new ArrayList<>();
        Program program = func.getProgram();

        try {
            // Function comment (plate comment)
            String funcComment = func.getComment();
            if (funcComment != null && !funcComment.isEmpty()) {
                Map<String, Object> map = new HashMap<>();
                map.put("address", String.format("0x%x", func.getEntryPoint().getOffset()));
                map.put("symbol_type", "comment");
                map.put("content", funcComment);
                map.put("confidence", 1.0);
                map.put("provenance", "user");
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("type", "function");
                map.put("metadata", metadata);
                symbols.add(map);
            }

            // EOL and PRE comments within the function
            ghidra.program.model.listing.Listing listing = program.getListing();
            ghidra.program.model.address.AddressSetView body = func.getBody();

            for (ghidra.program.model.address.Address addr : body.getAddresses(true)) {
                ghidra.program.model.listing.CodeUnit codeUnit = listing.getCodeUnitAt(addr);
                if (codeUnit == null) continue;

                String eolComment = codeUnit.getComment(ghidra.program.model.listing.CommentType.EOL);
                if (eolComment != null && !eolComment.isEmpty()) {
                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", addr.getOffset()));
                    map.put("symbol_type", "comment");
                    map.put("content", eolComment);
                    map.put("confidence", 1.0);
                    map.put("provenance", "user");
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("type", "eol");
                    metadata.put("function", getQualifiedFunctionName(func));
                    map.put("metadata", metadata);
                    symbols.add(map);
                }

                String preComment = codeUnit.getComment(ghidra.program.model.listing.CommentType.PRE);
                if (preComment != null && !preComment.isEmpty()) {
                    Map<String, Object> map = new HashMap<>();
                    map.put("address", String.format("0x%x", addr.getOffset()));
                    map.put("symbol_type", "comment");
                    map.put("content", preComment);
                    map.put("confidence", 1.0);
                    map.put("provenance", "user");
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("type", "pre");
                    metadata.put("function", getQualifiedFunctionName(func));
                    map.put("metadata", metadata);
                    symbols.add(map);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error collecting function comments: " + e.getMessage());
        }
        return symbols;
    }

    private Map<String, Object> collectLocalGraph(String scope) {
        if (plugin.getCurrentProgram() == null || analysisDB == null) {
            return null;
        }

        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        try {
            String programHash = plugin.getCurrentProgram().getExecutableSHA256();
            BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);

            if (graph == null || graph.getNodeCount() == 0) {
                Msg.warn(this, "No graph data found. Please index the binary first using the Semantic Graph tab.");
                return null;
            }

            // Step 1: Collect all node IDs to export
            java.util.Set<String> nodeIdsToExport = new java.util.HashSet<>();

            if ("function".equals(scope)) {
                // Just the current function and its immediate neighbors
                Function currentFunc = plugin.getCurrentFunction();
                if (currentFunc != null) {
                    KnowledgeNode funcNode = graph.getNodeByAddress(currentFunc.getEntryPoint().getOffset());
                    if (funcNode != null) {
                        nodeIdsToExport.add(funcNode.getId());
                        // Add 1-hop neighbors
                        for (KnowledgeNode neighbor : graph.getNeighborsBatch(funcNode.getId(), 1)) {
                            nodeIdsToExport.add(neighbor.getId());
                        }
                    }
                }
            } else {
                // Full binary - export all nodes
                for (NodeType nodeType : NodeType.values()) {
                    for (KnowledgeNode node : graph.getNodesByType(nodeType)) {
                        nodeIdsToExport.add(node.getId());
                    }
                }
            }

            // Step 2: BATCH fetch all nodes in ONE query
            java.util.Map<String, KnowledgeNode> nodeCache = graph.getNodes(nodeIdsToExport);

            // Step 3: BATCH fetch all edges in ONE query
            java.util.List<BinaryKnowledgeGraph.GraphEdge> allEdges = graph.getEdgesForNodes(nodeIdsToExport);

            // Step 4: Process nodes from cache
            for (KnowledgeNode node : nodeCache.values()) {
                nodes.add(nodeToExportMap(node));
            }

            // Step 5: Process edges using cache
            for (BinaryKnowledgeGraph.GraphEdge edge : allEdges) {
                // Only include edges where both endpoints are in our export set
                if (nodeIdsToExport.contains(edge.getTargetId())) {
                    KnowledgeNode sourceNode = nodeCache.get(edge.getSourceId());
                    KnowledgeNode targetNode = nodeCache.get(edge.getTargetId());

                    if (sourceNode != null && targetNode != null) {
                        Map<String, Object> edgeMap = new HashMap<>();
                        edgeMap.put("source_address", sourceNode.getAddress() != null ? String.format("0x%x", sourceNode.getAddress()) : "0x0");
                        edgeMap.put("target_address", targetNode.getAddress() != null ? String.format("0x%x", targetNode.getAddress()) : "0x0");
                        edgeMap.put("source_name", sourceNode.getName());
                        edgeMap.put("target_name", targetNode.getName());
                        edgeMap.put("edge_type", edge.getType().name().toLowerCase());
                        edgeMap.put("weight", edge.getWeight());
                        edges.add(edgeMap);
                    }
                }
            }

            Msg.info(this, String.format("Collected %d nodes and %d edges for export", nodes.size(), edges.size()));

        } catch (Exception e) {
            Msg.error(this, "Error collecting graph: " + e.getMessage(), e);
        }

        if (nodes.isEmpty()) {
            return null;
        }

        Map<String, Object> graphData = new HashMap<>();
        graphData.put("nodes", nodes);
        graphData.put("edges", edges);
        return graphData;
    }

    /**
     * Convert a KnowledgeNode to a Map for export.
     */
    private Map<String, Object> nodeToExportMap(KnowledgeNode node) {
        Map<String, Object> nodeMap = new HashMap<>();
        nodeMap.put("address", node.getAddress() != null ? String.format("0x%x", node.getAddress()) : "0x0");
        nodeMap.put("node_type", node.getType().name().toLowerCase());
        nodeMap.put("name", node.getName());
        nodeMap.put("signature", node.getSignature());
        nodeMap.put("decompiled_code", node.getDecompiledCode());
        nodeMap.put("disassembly", node.getDisassembly());
        nodeMap.put("raw_content", node.getRawContent());
        nodeMap.put("llm_summary", node.getLlmSummary());
        nodeMap.put("confidence", node.getConfidence());
        nodeMap.put("provenance", node.isUserEdited() ? "user" :
            (node.getLlmSummary() != null && !node.getLlmSummary().isEmpty() ? "llm" : "decompiler"));

        // Add security-related fields if present
        if (node.getSecurityFlags() != null && !node.getSecurityFlags().isEmpty()) {
            nodeMap.put("security_flags", new ArrayList<>(node.getSecurityFlags()));
        }
        if (node.getNetworkAPIs() != null && !node.getNetworkAPIs().isEmpty()) {
            nodeMap.put("network_apis", new ArrayList<>(node.getNetworkAPIs()));
        }
        if (node.getFileIOAPIs() != null && !node.getFileIOAPIs().isEmpty()) {
            nodeMap.put("file_io_apis", new ArrayList<>(node.getFileIOAPIs()));
        }
        if (node.getIPAddresses() != null && !node.getIPAddresses().isEmpty()) {
            nodeMap.put("ip_addresses", new ArrayList<>(node.getIPAddresses()));
        }
        if (node.getURLs() != null && !node.getURLs().isEmpty()) {
            nodeMap.put("urls", new ArrayList<>(node.getURLs()));
        }
        if (node.getFilePaths() != null && !node.getFilePaths().isEmpty()) {
            nodeMap.put("file_paths", new ArrayList<>(node.getFilePaths()));
        }
        if (node.getDomains() != null && !node.getDomains().isEmpty()) {
            nodeMap.put("domains", new ArrayList<>(node.getDomains()));
        }
        if (node.getRegistryKeys() != null && !node.getRegistryKeys().isEmpty()) {
            nodeMap.put("registry_keys", new ArrayList<>(node.getRegistryKeys()));
        }
        if (node.getRiskLevel() != null) {
            nodeMap.put("risk_level", node.getRiskLevel());
        }
        if (node.getActivityProfile() != null) {
            nodeMap.put("activity_profile", node.getActivityProfile());
        }
        nodeMap.put("analysis_depth", node.getAnalysisDepth());

        return nodeMap;
    }

    /**
     * Build a map of external function names to their PLT/thunk stub addresses.
     * Ghidra's thunk functions (PLT stubs) point to external functions but have
     * real addresses in the binary's address space.
     */
    private Map<String, Long> buildExternalAddressMap() {
        Map<String, Long> map = new HashMap<>();
        Program program = plugin.getCurrentProgram();
        if (program == null) return map;

        FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (func.isThunk()) {
                Function thunked = func.getThunkedFunction(true);
                if (thunked != null && thunked.isExternal()) {
                    map.putIfAbsent(thunked.getName(), func.getEntryPoint().getOffset());
                }
            }
        }
        Msg.info(this, "Resolved " + map.size() + " external function PLT addresses");
        return map;
    }

    /**
     * Resolve address for an external function.
     * Returns the PLT/thunk stub address if available, null otherwise.
     */
    private Long resolveExternalAddress(String name) {
        if (externalAddressMap != null && externalAddressMap.containsKey(name)) {
            return externalAddressMap.get(name);
        }
        return null; // Server handles dedup by name for address-0 external nodes
    }

    /**
     * Get the fully qualified name of a function including its namespace.
     * Delegates to shared utility in SymGraphUtils.
     */
    private String getQualifiedFunctionName(Function func) {
        return ghidrassist.services.symgraph.SymGraphUtils.getQualifiedFunctionName(func);
    }
}
