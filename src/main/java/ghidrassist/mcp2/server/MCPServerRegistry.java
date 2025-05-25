package ghidrassist.mcp2.server;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Registry for managing MCP server configurations.
 * Handles persistence, validation, and server lifecycle.
 */
public class MCPServerRegistry {
    
    private static MCPServerRegistry instance;
    private static final String PREFERENCE_KEY = "GhidrAssist.MCPServers";
    
    private List<MCPServerConfig> servers = new ArrayList<>();
    private MCPServerRegistryHandler handler;
    
    /**
     * Interface for handling registry events
     */
    public interface MCPServerRegistryHandler {
        void onServersChanged(List<MCPServerConfig> servers);
        void onServerAdded(MCPServerConfig server);
        void onServerRemoved(MCPServerConfig server);
        void onServerUpdated(MCPServerConfig server);
    }
    
    private MCPServerRegistry() {
        loadServers();
    }
    
    /**
     * Get singleton instance
     */
    public static synchronized MCPServerRegistry getInstance() {
        if (instance == null) {
            instance = new MCPServerRegistry();
        }
        return instance;
    }
    
    /**
     * Set event handler
     */
    public void setHandler(MCPServerRegistryHandler handler) {
        this.handler = handler;
    }
    
    /**
     * Add a new server configuration
     */
    public void addServer(MCPServerConfig server) {
        if (server == null || !server.isValid()) {
            throw new IllegalArgumentException("Invalid server configuration");
        }
        
        // Check for duplicate names
        if (servers.stream().anyMatch(s -> s.getName().equals(server.getName()))) {
            throw new IllegalArgumentException("Server with name '" + server.getName() + "' already exists");
        }
        
        servers.add(server);
        saveServers();
        
        if (handler != null) {
            handler.onServerAdded(server);
            handler.onServersChanged(new ArrayList<>(servers));
        }
        
        Msg.info(this, "Added MCP server: " + server.getName());
    }
    
    /**
     * Remove a server configuration
     */
    public boolean removeServer(String serverName) {
        MCPServerConfig toRemove = servers.stream()
            .filter(s -> s.getName().equals(serverName))
            .findFirst()
            .orElse(null);
        
        if (toRemove != null) {
            servers.remove(toRemove);
            saveServers();
            
            if (handler != null) {
                handler.onServerRemoved(toRemove);
                handler.onServersChanged(new ArrayList<>(servers));
            }
            
            Msg.info(this, "Removed MCP server: " + serverName);
            return true;
        }
        
        return false;
    }
    
    /**
     * Update an existing server configuration
     */
    public boolean updateServer(MCPServerConfig updatedServer) {
        if (updatedServer == null || !updatedServer.isValid()) {
            throw new IllegalArgumentException("Invalid server configuration");
        }
        
        for (int i = 0; i < servers.size(); i++) {
            if (servers.get(i).getName().equals(updatedServer.getName())) {
                servers.set(i, updatedServer);
                saveServers();
                
                if (handler != null) {
                    handler.onServerUpdated(updatedServer);
                    handler.onServersChanged(new ArrayList<>(servers));
                }
                
                Msg.info(this, "Updated MCP server: " + updatedServer.getName());
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Get all server configurations
     */
    public List<MCPServerConfig> getAllServers() {
        return new ArrayList<>(servers);
    }
    
    /**
     * Get only enabled server configurations
     */
    public List<MCPServerConfig> getEnabledServers() {
        return servers.stream()
            .filter(MCPServerConfig::isEnabled)
            .collect(Collectors.toList());
    }
    
    /**
     * Get server by name
     */
    public MCPServerConfig getServer(String name) {
        return servers.stream()
            .filter(s -> s.getName().equals(name))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * Check if any servers are configured
     */
    public boolean hasServers() {
        return !servers.isEmpty();
    }
    
    /**
     * Check if any servers are enabled
     */
    public boolean hasEnabledServers() {
        return servers.stream().anyMatch(MCPServerConfig::isEnabled);
    }
    
    /**
     * Enable/disable a server
     */
    public boolean setServerEnabled(String serverName, boolean enabled) {
        MCPServerConfig server = getServer(serverName);
        if (server != null) {
            server.setEnabled(enabled);
            saveServers();
            
            if (handler != null) {
                handler.onServerUpdated(server);
                handler.onServersChanged(new ArrayList<>(servers));
            }
            
            Msg.info(this, (enabled ? "Enabled" : "Disabled") + " MCP server: " + serverName);
            return true;
        }
        return false;
    }
    
    /**
     * Initialize with default servers if none exist
     */
    public void initializeDefaults() {
        if (servers.isEmpty()) {
            // Add default GhidraMCP server (disabled by default)
            MCPServerConfig defaultServer = MCPServerConfig.createGhidraMCPDefault();
            defaultServer.setEnabled(false); // Disabled by default until user enables
            try {
                servers.add(defaultServer); // Add directly to avoid validation during initialization
                saveServers();
            } catch (Exception e) {
                Msg.warn(this, "Failed to create default MCP server: " + e.getMessage());
            }
            
            Msg.info(this, "Initialized default MCP server configurations");
        }
    }
    
    /**
     * Load servers from preferences
     */
    private void loadServers() {
        String serversJson = Preferences.getProperty(PREFERENCE_KEY, "[]");
        
        try {
            Gson gson = new Gson();
            Type listType = new TypeToken<List<MCPServerConfig>>(){}.getType();
            List<MCPServerConfig> loadedServers = gson.fromJson(serversJson, listType);
            
            if (loadedServers != null) {
                // Validate and migrate loaded servers
                servers = loadedServers.stream()
                    .filter(MCPServerConfig::isValid)
                    .map(this::migrateServerConfig)  // Apply migration
                    .collect(Collectors.toList());
                
                Msg.info(this, "Loaded " + servers.size() + " MCP server configurations");
                
                // Save migrated configurations
                saveServers();
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to load MCP server configurations: " + e.getMessage());
            servers = new ArrayList<>();
        }
        
        // Initialize defaults if no servers loaded
        if (servers.isEmpty()) {
            initializeDefaults();
        }
    }
    
    /**
     * Migrate server configuration to apply new timeout defaults
     */
    private MCPServerConfig migrateServerConfig(MCPServerConfig server) {
        boolean needsMigration = false;
        
        // Update old timeout values to new optimized defaults
        if (server.getConnectionTimeout() >= 10) {  // Old default was 10 seconds
            server.setConnectionTimeout(5);  // New optimized default
            needsMigration = true;
        }
        
        if (server.getRequestTimeout() >= 30) {  // Old default was 30 seconds  
            server.setRequestTimeout(15);  // New optimized default
            needsMigration = true;
        }
        
        if (needsMigration) {
            Msg.info(this, "Migrated timeout settings for MCP server: " + server.getName() + 
                     " (connection: " + server.getConnectionTimeout() + "s, request: " + server.getRequestTimeout() + "s)");
        }
        
        return server;
    }
    
    /**
     * Save servers to preferences
     */
    private void saveServers() {
        try {
            Gson gson = new Gson();
            String serversJson = gson.toJson(servers);
            Preferences.setProperty(PREFERENCE_KEY, serversJson);
            Preferences.store();
        } catch (Exception e) {
            Msg.error(this, "Failed to save MCP server configurations: " + e.getMessage());
        }
    }
    
    /**
     * Clear all servers (for testing/reset)
     */
    public void clearAllServers() {
        servers.clear();
        saveServers();
        
        if (handler != null) {
            handler.onServersChanged(new ArrayList<>(servers));
        }
        
        Msg.info(this, "Cleared all MCP server configurations");
    }
    
    /**
     * Get status summary
     */
    public String getStatusSummary() {
        long enabledCount = servers.stream().filter(MCPServerConfig::isEnabled).count();
        return String.format("%d servers (%d enabled)", servers.size(), enabledCount);
    }
}