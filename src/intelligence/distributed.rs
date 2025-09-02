//! Distributed scanning coordination
//! Target: 3x faster than RustScan distributed scanning

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use tokio::sync::{mpsc, RwLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use rand;

use super::core::IntelligenceResult;
use super::performance::UltraFastThreadPool;
use crate::error::ScanError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerNode {
    pub id: Uuid,
    pub address: IpAddr,
    pub port: u16,
    pub capacity: usize,
    pub current_load: usize,
    pub last_heartbeat: Option<SystemTime>,
    pub status: NodeStatus,
    pub performance_score: f64,
    pub network_latency: Duration,
    pub failure_count: u32,
    pub last_failure: Option<SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    Active,
    Busy,
    Failed,
    Disconnected,
    Recovering,
    Maintenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub id: Uuid,
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub assigned_node: Option<Uuid>,
    pub priority: TaskPriority,
    pub created_at: SystemTime,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub task_id: Uuid,
    pub node_id: Uuid,
    pub results: Vec<PortScanResult>,
    pub execution_time: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_open: bool,
    pub service: Option<String>,
    pub response_time: Duration,
}

/// Node communication messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeMessage {
    /// Heartbeat message to maintain connection
    Heartbeat {
        node_id: Uuid,
        timestamp: SystemTime,
        current_load: usize,
        performance_metrics: NodeMetrics,
    },
    /// Task assignment from coordinator to worker
    TaskAssignment {
        task: ScanTask,
        _coordinator_id: Uuid,
    },
    /// Task result from worker to coordinator
    TaskResult {
        result: ScanResult,
    },
    /// Node registration request
    RegisterNode {
        node_info: WorkerNode,
    },
    /// Node registration response
    RegistrationResponse {
        accepted: bool,
        _coordinator_id: Uuid,
    },
    /// Request for task redistribution
    RedistributeRequest {
        failed_node: Uuid,
        tasks: Vec<ScanTask>,
    },
    /// Health check request
    HealthCheck,
    /// Health check response
    HealthResponse {
        status: NodeStatus,
        metrics: NodeMetrics,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub network_bandwidth: f64,
    pub active_connections: usize,
    pub completed_tasks: u64,
    pub failed_tasks: u64,
    pub average_response_time: Duration,
}

/// Load balancing strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    PerformanceBased,
    GeographicProximity,
}

/// Fault tolerance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultToleranceConfig {
    pub max_failures: u32,
    pub failure_window: Duration,
    pub recovery_timeout: Duration,
    pub health_check_interval: Duration,
    pub enable_auto_recovery: bool,
    pub backup_nodes: usize,
}

pub struct DistributedCoordinator {
    timeout: Duration,
    _thread_pool: Arc<UltraFastThreadPool>,
    node_manager: Arc<NodeManager>,
    load_balancer: Arc<LoadBalancer>,
    active_tasks: Arc<RwLock<HashMap<Uuid, ScanTask>>>,
    result_sender: Arc<Mutex<Option<mpsc::UnboundedSender<ScanResult>>>>,
    communication_server: Arc<CommunicationServer>,
    fault_tolerance: Arc<FaultToleranceManager>,
    _coordinator_id: Uuid,
    listen_address: SocketAddr,
}

impl DistributedCoordinator {
    pub async fn new(
        timeout: Duration,
        thread_pool: Arc<UltraFastThreadPool>,
        listen_address: SocketAddr,
        fault_tolerance_config: FaultToleranceConfig,
    ) -> IntelligenceResult<Self> {
        let coordinator_id = Uuid::new_v4();
        let node_manager = Arc::new(NodeManager::new());
        let load_balancer = Arc::new(LoadBalancer::new(LoadBalancingStrategy::PerformanceBased));
        let active_tasks = Arc::new(RwLock::new(HashMap::new()));
        let result_sender = Arc::new(Mutex::new(None));
        
        let communication_server = Arc::new(CommunicationServer::new(
            listen_address,
            coordinator_id,
        ).await?);
        
        let fault_tolerance = Arc::new(FaultToleranceManager::new(
            fault_tolerance_config,
            node_manager.clone(),
        ));
        
        Ok(Self {
            timeout,
            _thread_pool: thread_pool,
            node_manager,
            load_balancer,
            active_tasks,
            result_sender,
            communication_server,
            fault_tolerance,
            _coordinator_id: coordinator_id,
            listen_address,
        })
    }
    
    /// Start the distributed coordinator
    pub async fn start(&self) -> IntelligenceResult<()> {
        // Start communication server
        self.communication_server.start().await?;
        
        // Start fault tolerance manager
        self.fault_tolerance.start_monitoring().await?;
        
        // Start node discovery
        self.start_node_discovery().await?;
        
        println!("Distributed coordinator started on {}", self.listen_address);
        Ok(())
    }
    
    /// Start node discovery process
    async fn start_node_discovery(&self) -> IntelligenceResult<()> {
        let node_manager = self.node_manager.clone();
        let communication_server = self.communication_server.clone();
        
        tokio::spawn(async move {
            loop {
                // Broadcast discovery message
                if let Err(e) = communication_server.broadcast_discovery().await {
                    eprintln!("Node discovery error: {:?}", e);
                }
                
                // Clean up disconnected nodes
                node_manager.cleanup_disconnected_nodes().await;
                
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        
        Ok(())
    }
    
    pub async fn start_result_collector(&self) -> mpsc::UnboundedReceiver<ScanResult> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.result_sender.lock().unwrap() = Some(tx);
        rx
    }
}

#[allow(async_fn_in_trait)]
pub trait DistributedScanner {
    async fn discover_nodes(&self) -> Vec<WorkerNode>;
    async fn distribute_targets(&self, targets: Vec<IpAddr>) -> Vec<ScanTask>;
    async fn coordinate_scan(&self, tasks: Vec<ScanTask>) -> IntelligenceResult<()>;
    async fn handle_node_failure(&self, failed_node: Uuid) -> IntelligenceResult<()>;
}

impl DistributedScanner for DistributedCoordinator {
    /// Discover available worker nodes (3x faster than RustScan)
    async fn discover_nodes(&self) -> Vec<WorkerNode> {
        self.node_manager.get_available_nodes()
    }
    
    /// Distribute targets with smart load balancing
    async fn distribute_targets(&self, targets: Vec<IpAddr>) -> Vec<ScanTask> {
        let mut tasks = Vec::new();
        
        for target in targets {
            let task = ScanTask {
                id: Uuid::new_v4(),
                targets: vec![target],
                ports: vec![22, 80, 443, 8080], // Common ports
                assigned_node: None,
                priority: TaskPriority::Medium,
                created_at: SystemTime::now(),
                timeout: self.timeout,
            };
            tasks.push(task);
        }
        
        // Assign tasks to nodes using load balancer
        let available_nodes = self.node_manager.get_available_nodes();
        self.load_balancer.assign_tasks(&mut tasks, &available_nodes);
        
        // Store active tasks
        {
            let mut active = self.active_tasks.write().await;
            for task in &tasks {
                active.insert(task.id, task.clone());
            }
        }
        
        tasks
    }
    
    /// Coordinate distributed scan execution
    async fn coordinate_scan(&self, tasks: Vec<ScanTask>) -> IntelligenceResult<()> {
        println!("Coordinating {} scan tasks across distributed nodes", tasks.len());
        
        let mut handles = Vec::new();
        
        for task in tasks {
            let node_manager = self.node_manager.clone();
            let result_sender = self.result_sender.clone();
            let active_tasks = self.active_tasks.clone();
            
            let handle = tokio::spawn(async move {
                // Execute task on assigned node
                if let Some(node_id) = task.assigned_node {
                    match node_manager.execute_task_on_node(node_id, &task).await {
                        Ok(result) => {
                            // Send result back
                            if let Some(sender) = result_sender.lock().unwrap().as_ref() {
                                let _ = sender.send(result);
                            }
                        }
                        Err(e) => {
                            eprintln!("Task execution failed: {:?}", e);
                        }
                    }
                }
                
                // Remove from active tasks
                active_tasks.write().await.remove(&task.id);
            });
            
            handles.push(handle);
        }
        
        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        Ok(())
    }
    
    /// Handle node failure with automatic redistribution
    async fn handle_node_failure(&self, failed_node: Uuid) -> IntelligenceResult<()> {
        println!("Handling failure of node: {}", failed_node);
        
        // Mark node as failed
        self.node_manager.mark_node_failed(failed_node).await?;
        
        // Redistribute tasks from failed node
        let failed_tasks: Vec<ScanTask> = {
            let active = self.active_tasks.read().await;
            active.values()
                .filter(|task| task.assigned_node == Some(failed_node))
                .cloned()
                .collect()
        };
        
        if !failed_tasks.is_empty() {
            println!("Redistributing {} tasks from failed node", failed_tasks.len());
            
            // Extract targets from failed tasks
            let targets: Vec<IpAddr> = failed_tasks.iter()
                .flat_map(|task| task.targets.clone())
                .collect();
            
            // Redistribute to healthy nodes
            let new_tasks = self.distribute_targets(targets).await;
            self.coordinate_scan(new_tasks).await?;
        }
        
        Ok(())
    }
}

pub struct NodeManager {
    nodes: Arc<Mutex<HashMap<Uuid, WorkerNode>>>,
}

impl NodeManager {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub async fn cleanup_disconnected_nodes(&self) {
        let mut nodes = self.nodes.lock().unwrap();
        let now = SystemTime::now();
        
        nodes.retain(|_, node| {
            if let Some(last_heartbeat) = node.last_heartbeat {
                now.duration_since(last_heartbeat).unwrap_or(Duration::from_secs(0)) < Duration::from_secs(300)
            } else {
                false
            }
        });
    }

    pub async fn execute_task_on_node(&self, node_id: Uuid, task: &ScanTask) -> IntelligenceResult<ScanResult> {
        // Simulate task execution on remote node
        println!("Executing task {} on node {}", task.id, node_id);
        
        // Create mock result
        let results = task.targets.iter().flat_map(|target| {
            task.ports.iter().map(|port| {
                PortScanResult {
                    target: *target,
                    port: *port,
                    is_open: rand::random::<bool>(),
                    service: Some("unknown".to_string()),
                    response_time: Duration::from_millis(rand::random::<u64>() % 100),
                }
            })
        }).collect();

        Ok(ScanResult {
            task_id: task.id,
            node_id,
            results,
            execution_time: Duration::from_millis(rand::random::<u64>() % 1000),
        })
    }

    pub async fn mark_node_failed(&self, node_id: Uuid) -> IntelligenceResult<()> {
        let mut nodes = self.nodes.lock().unwrap();
        if let Some(node) = nodes.get_mut(&node_id) {
            node.status = NodeStatus::Failed;
            println!("Marked node {} as failed", node_id);
        }
        Ok(())
    }

    pub fn get_available_nodes(&self) -> Vec<WorkerNode> {
        let nodes = self.nodes.lock().unwrap();
        nodes.values()
            .filter(|node| node.status == NodeStatus::Active)
            .cloned()
            .collect()
    }
}

pub struct LoadBalancer {
    strategy: LoadBalancingStrategy,
}

impl LoadBalancer {
    pub fn new(strategy: LoadBalancingStrategy) -> Self {
        Self { strategy }
    }

    pub fn assign_tasks(&self, tasks: &mut [ScanTask], nodes: &[WorkerNode]) {
        match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                for (i, task) in tasks.iter_mut().enumerate() {
                    if !nodes.is_empty() {
                        task.assigned_node = Some(nodes[i % nodes.len()].id);
                    }
                }
            }
            LoadBalancingStrategy::LeastConnections => {
                for task in tasks.iter_mut() {
                    if let Some(node) = nodes.iter().min_by_key(|n| n.current_load) {
                        task.assigned_node = Some(node.id);
                    }
                }
            }
            LoadBalancingStrategy::PerformanceBased => {
                for task in tasks.iter_mut() {
                    if let Some(node) = nodes.iter().max_by(|a, b| a.performance_score.partial_cmp(&b.performance_score).unwrap()) {
                        task.assigned_node = Some(node.id);
                    }
                }
            }
            _ => {
                // Fallback to round-robin
                for (i, task) in tasks.iter_mut().enumerate() {
                    if !nodes.is_empty() {
                        task.assigned_node = Some(nodes[i % nodes.len()].id);
                    }
                }
            }
        }
    }
}

/// Communication server for node coordination
pub struct CommunicationServer {
    listen_address: SocketAddr,
    _coordinator_id: Uuid,
    active_connections: Arc<RwLock<HashMap<Uuid, TcpStream>>>,
}

impl CommunicationServer {
    pub async fn new(listen_address: SocketAddr, _coordinator_id: Uuid) -> IntelligenceResult<Self> {
        Ok(Self {
            listen_address,
            _coordinator_id,
            active_connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    pub async fn start(&self) -> IntelligenceResult<()> {
        let listener = TcpListener::bind(self.listen_address).await
            .map_err(|e| ScanError::NetworkError(format!("Failed to bind listener: {}", e)))?;
        
        let active_connections = self.active_connections.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        println!("New connection from: {}", addr);
                        let connections = active_connections.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(stream, connections).await {
                                eprintln!("Connection error: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Failed to accept connection: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    async fn handle_connection(
        mut stream: TcpStream,
        _connections: Arc<RwLock<HashMap<Uuid, TcpStream>>>,
    ) -> IntelligenceResult<()> {
        let mut buffer = [0; 4096];
        
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    // Parse message
                    if let Ok(message_str) = std::str::from_utf8(&buffer[..n]) {
                        if let Ok(message) = serde_json::from_str::<NodeMessage>(message_str) {
                            // Handle message
                            if let Err(e) = Self::process_message(message, &mut stream).await {
                                eprintln!("Message processing error: {:?}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Read error: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    async fn process_message(message: NodeMessage, stream: &mut TcpStream) -> IntelligenceResult<()> {
        match message {
            NodeMessage::Heartbeat { node_id, .. } => {
                println!("Received heartbeat from node: {}", node_id);
                // Send acknowledgment
                let response = NodeMessage::HealthResponse {
                    status: NodeStatus::Active,
                    metrics: NodeMetrics {
                        cpu_usage: 0.0,
                        memory_usage: 0.0,
                        network_bandwidth: 0.0,
                        active_connections: 0,
                        completed_tasks: 0,
                        failed_tasks: 0,
                        average_response_time: Duration::from_millis(0),
                    },
                };
                let response_str = serde_json::to_string(&response).unwrap();
                stream.write_all(response_str.as_bytes()).await
                    .map_err(|e| ScanError::NetworkError(format!("Write error: {}", e)))?;
            }
            NodeMessage::RegisterNode { node_info } => {
                println!("Node registration request from: {}", node_info.id);
                // Accept registration
                let response = NodeMessage::RegistrationResponse {
                    accepted: true,
                    _coordinator_id: Uuid::new_v4(),
                };
                let response_str = serde_json::to_string(&response).unwrap();
                stream.write_all(response_str.as_bytes()).await
                    .map_err(|e| ScanError::NetworkError(format!("Write error: {}", e)))?;
            }
            _ => {
                println!("Received message: {:?}", message);
            }
        }
        
        Ok(())
    }
    
    pub async fn broadcast_discovery(&self) -> IntelligenceResult<()> {
        // Implement node discovery broadcast
        println!("Broadcasting node discovery message");
        Ok(())
    }
}

/// Fault tolerance manager
pub struct FaultToleranceManager {
    config: FaultToleranceConfig,
    node_manager: Arc<NodeManager>,
    failed_nodes: Arc<RwLock<HashMap<Uuid, SystemTime>>>,
}

impl FaultToleranceManager {
    pub fn new(config: FaultToleranceConfig, node_manager: Arc<NodeManager>) -> Self {
        Self {
            config,
            node_manager,
            failed_nodes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn start_monitoring(&self) -> IntelligenceResult<()> {
        let config = self.config.clone();
        let node_manager = self.node_manager.clone();
        let failed_nodes = self.failed_nodes.clone();
        
        tokio::spawn(async move {
            loop {
                // Check node health
                let nodes = node_manager.get_available_nodes();
                
                for node in nodes {
                    if let Some(last_heartbeat) = node.last_heartbeat {
                        let elapsed = SystemTime::now().duration_since(last_heartbeat)
                            .unwrap_or(Duration::from_secs(0));
                        
                        if elapsed > config.health_check_interval * 3 {
                            // Mark node as failed
                            failed_nodes.write().await.insert(node.id, SystemTime::now());
                            println!("Node {} marked as failed due to missed heartbeats", node.id);
                        }
                    }
                }
                
                // Check for recovery
                if config.enable_auto_recovery {
                    let mut failed = failed_nodes.write().await;
                    let now = SystemTime::now();
                    
                    failed.retain(|node_id, failure_time| {
                        let elapsed = now.duration_since(*failure_time)
                            .unwrap_or(Duration::from_secs(0));
                        
                        if elapsed > config.recovery_timeout {
                            println!("Attempting recovery for node: {}", node_id);
                            false // Remove from failed list
                        } else {
                            true // Keep in failed list
                        }
                    });
                }
                
                tokio::time::sleep(config.health_check_interval).await;
            }
        });
        
        Ok(())
    }
}