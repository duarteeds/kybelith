use std::collections::{HashMap, HashSet};
use log::{debug, info};
use crate::p2p::types::NodeId;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TreeMetrics {
    pub max_depth: usize,
    pub avg_depth: f64,
    pub node_count: usize,     
    pub leaf_count: usize,     
    pub branching_factor: f64, 
}

/// Representa uma árvore de expansão para otimizar o broadcast na rede P2P
/// 
/// A árvore de expansão é uma estrutura que permite enviar mensagens para todos os nós
/// da rede sem redundância, evitando loops de mensagens que causariam inundação da rede.
pub struct SpanningTree {
    /// O nó raiz da árvore de expansão
    root: NodeId,
    /// Mapa de nós para seus filhos (conexões diretas)
    children: HashMap<NodeId, HashSet<NodeId>>,
    /// Mapa de nós para seus pais (nó que o conectou à rede)
    parent: HashMap<NodeId, NodeId>,
    /// Mapa de nós para sua profundidade na árvore (distância da raiz)
    depth: HashMap<NodeId, usize>,
    /// Cache de caminhos entre nós
    path_cache: HashMap<(NodeId, NodeId), Vec<NodeId>>,
    /// Contador de mensagens por ID
    message_seen: HashMap<String, (HashSet<NodeId>, u64)>,
}

impl SpanningTree {
    /// Cria uma nova árvore de expansão com o nó especificado como raiz
    pub fn new(root: NodeId) -> Self {
        let mut children = HashMap::new();
        let mut depth = HashMap::new();
        
        // Inicializa o nó raiz
        children.insert(root.clone(), HashSet::new());
        depth.insert(root.clone(), 0);
        
        Self { 
            root,
            children,
            parent: HashMap::new(),
            depth,
            path_cache: HashMap::new(),
            message_seen: HashMap::new(),
        }
    }

    /// Obtém métricas sobre o consenso para monitoramento
    pub fn get_metrics(&self) -> TreeMetrics {
        let mut max_depth = 0;
        let mut total_depth = 0;
        let node_count = self.children.len();
        let mut leaf_count = 0;
        let mut branch_sum = 0;
        let mut branch_nodes = 0;
        
        for (node_id, children) in &self.children {
            // Update max depth
            if let Some(depth) = self.depth.get(node_id) {
                max_depth = max_depth.max(*depth);
                total_depth += depth;
            }
            
            // Count leaf nodes
            if children.is_empty() {
                leaf_count += 1;
            } else {
                branch_sum += children.len();
                branch_nodes += 1;
            }
        }
        
        let avg_depth = if node_count > 0 {
            total_depth as f64 / node_count as f64
        } else {
            0.0
        };
        
        let branching_factor = if branch_nodes > 0 {
            branch_sum as f64 / branch_nodes as f64
        } else {
            0.0
        };
        
        TreeMetrics {
            max_depth,
            avg_depth,
            node_count,
            leaf_count,
            branching_factor,
        }
    }

    /// Retorna o nó raiz da árvore
    pub fn get_root(&self) -> &NodeId {
        &self.root
    }

    /// Adiciona um nó à árvore
    pub fn add_node(&mut self, node_id: NodeId, parent_id: NodeId) -> bool {
        // Se o nó já existe, não fazemos nada
        if self.children.contains_key(&node_id) {
            debug!("Node {} already exists in spanning tree", node_id);
            return false;
        }

        // Verificamos se o pai existe
        if !self.children.contains_key(&parent_id) {
            debug!("Parent node {} does not exist in spanning tree", parent_id);
            return false;
        }

        // Adicionamos o nó aos filhos do pai
        if let Some(children) = self.children.get_mut(&parent_id) {
            children.insert(node_id.clone());
        }

        // Inicializamos a lista de filhos para o novo nó
        self.children.insert(node_id.clone(), HashSet::new());
        
        // Definimos o pai do nó
        self.parent.insert(node_id.clone(), parent_id.clone());
        
        // Definimos a profundidade do nó
        if let Some(parent_depth) = self.depth.get(&parent_id) {
            self.depth.insert(node_id.clone(), parent_depth + 1);
        }

        // Limpamos o cache de caminhos que podem ser afetados pela adição deste nó
        self.path_cache.clear();

        info!("Added node {} to spanning tree with parent {}", node_id, parent_id);
        true
    }

    /// Remove um nó da árvore e reorganiza seus filhos
    pub fn remove_node(&mut self, node_id: &NodeId) -> bool {
        if !self.children.contains_key(node_id) {
            return false;
        }

        // Se o nó for a raiz, não podemos removê-lo
        if node_id == &self.root {
            debug!("Cannot remove root node from spanning tree");
            return false;
        }

        // Obtém o pai do nó antes de remover
        let parent_id = if let Some(parent) = self.parent.get(node_id) {
            parent.clone()
        } else {
            return false;
        };

        // Obtém os filhos do nó
        let children = if let Some(children) = self.children.get(node_id) {
            children.clone()
        } else {
            HashSet::new()
        };

        // Para cada filho, atualiza seu pai para o avô
        for child in &children {
            self.parent.insert(child.clone(), parent_id.clone());
            
            // Atualiza a profundidade do filho e seus descendentes
            if let Some(parent_depth) = self.depth.get(&parent_id) {
                self.update_depth(child, parent_depth + 1);
            }
            
            // Adiciona o filho aos filhos do avô
            if let Some(parent_children) = self.children.get_mut(&parent_id) {
                parent_children.insert(child.clone());
            }
        }

        // Remove o nó dos filhos do pai
        if let Some(parent_children) = self.children.get_mut(&parent_id) {
            parent_children.remove(node_id);
        }

        // Remove o nó e suas entradas
        self.children.remove(node_id);
        self.parent.remove(node_id);
        self.depth.remove(node_id);

        // Limpa o cache de caminhos
        self.path_cache.clear();

        info!("Removed node {} from spanning tree", node_id);
        true
    }

    /// Atualiza recursivamente a profundidade de um nó e seus descendentes
    fn update_depth(&mut self, node_id: &NodeId, new_depth: usize) {
        // Atualiza a profundidade do nó
        self.depth.insert(node_id.clone(), new_depth);
        
        // Para cada filho, atualiza sua profundidade
        if let Some(children) = self.children.get(node_id).cloned() {
            for child in children {
                self.update_depth(&child, new_depth + 1);
            }
        }
    }

    /// Determina se uma mensagem deve ser encaminhada de um nó para outro
    /// 
    /// Isso é usado para evitar loops de mensagens na rede.
    pub fn should_forward(&mut self, message_id: &str, from_node: &NodeId, to_node: &NodeId) -> bool {
    if from_node == to_node {
        return false;
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let message_entry = self.message_seen.entry(message_id.to_string())
        .or_insert((HashSet::new(), now));
    
    if message_entry.0.contains(to_node) {
        return false;
    }
    
    message_entry.0.insert(to_node.clone());

    if let Some(children) = self.children.get(from_node) {
        if children.contains(to_node) {
            return true;
        }
    }

    if let Some(parent) = self.parent.get(from_node) {
        if parent == to_node {
            return true;
        }
    }

    false
}

    /// Versão não mutável do should_forward para uso em casos onde não podemos obter uma referência mutável
    pub fn should_forward_readonly(&self, from_node: &NodeId, to_node: &NodeId) -> bool {
        // Não encaminhamos para o remetente
        if from_node == to_node {
            return false;
        }

        // Se o nó é filho direto do remetente na árvore, encaminhamos
        if let Some(children) = self.children.get(from_node) {
            if children.contains(to_node) {
                return true;
            }
        }

        // Se o nó é pai do remetente na árvore, encaminhamos
        if let Some(parent) = self.parent.get(from_node) {
            if parent == to_node {
                return true;
            }
        }

        // Caso contrário, não encaminhamos
        false
    }

    /// Encontra o caminho mais curto entre dois nós na árvore
    pub fn find_path(&mut self, from: &NodeId, to: &NodeId) -> Option<Vec<NodeId>> {
        // Verifica se os nós existem
        if !self.children.contains_key(from) || !self.children.contains_key(to) {
            return None;
        }

        // Checa se o caminho está no cache
        let cache_key = (from.clone(), to.clone());
        if let Some(path) = self.path_cache.get(&cache_key) {
            return Some(path.clone());
        }

        // Encontra o ancestral comum
        let mut path = Vec::new();
        
        // Construir caminho do nó 'from' até a raiz
        let mut from_path = Vec::new();
        let mut current = from.clone();
        from_path.push(current.clone());
        
        while let Some(parent) = self.parent.get(&current) {
            from_path.push(parent.clone());
            current = parent.clone();
        }
        
        // Construir caminho do nó 'to' até a raiz
        let mut to_path = Vec::new();
        let mut current = to.clone();
        to_path.push(current.clone());
        
        while let Some(parent) = self.parent.get(&current) {
            to_path.push(parent.clone());
            current = parent.clone();
        }
        
        // Encontrar o ancestral comum
        let mut common_ancestor = None;
        for from_node in &from_path {
            if to_path.contains(from_node) {
                common_ancestor = Some(from_node.clone());
                break;
            }
        }
        
        // Se não encontrarmos um ancestral comum, não há caminho
        let common = match common_ancestor {
            Some(node) => node,
            None => return None,
        };
        
        // Construir o caminho: from -> ancestral -> to
        // Primeiro adiciona o caminho de 'from' até o ancestral comum
        for node in from_path {
            path.push(node.clone());
            if node == common {
                break;
            }
        }
        
        // Depois adiciona o caminho do ancestral comum até 'to', em ordem reversa
        let mut to_reverse_path = Vec::new();
        for node in to_path {
            if node == common {
                break;
            }
            to_reverse_path.push(node);
        }
        to_reverse_path.reverse();
        
        path.extend(to_reverse_path);
        
        // Armazena o caminho no cache
        self.path_cache.insert(cache_key, path.clone());
        
        Some(path)
    }

    /// Retorna a lista de nós filhos diretos
    pub fn get_children(&self, node_id: &NodeId) -> Vec<NodeId> {
        if let Some(children) = self.children.get(node_id) {
            children.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Retorna todos os nós na árvore
    pub fn get_all_nodes(&self) -> Vec<NodeId> {
        self.children.keys().cloned().collect()
    }

    /// Retorna a profundidade do nó na árvore
    pub fn get_depth(&self, node_id: &NodeId) -> Option<usize> {
        self.depth.get(node_id).cloned()
    }

    /// Otimiza a árvore balanceando a profundidade dos nós
    pub fn optimize(&mut self) -> usize {
        let metrics_before = self.get_metrics();
        let mut changes = 0;
        
        // First pass: identify nodes with high depth
        let target_max_depth = 4; // Target a max depth of 4 for good message propagation
        
        if metrics_before.max_depth <= target_max_depth {
            debug!("Tree already optimized (max depth: {})", metrics_before.max_depth);
            return 0;
        }
        
        // Find nodes that are too deep
        let mut deep_nodes = Vec::new();
        for (node_id, depth) in &self.depth {
            if *depth > target_max_depth && node_id != &self.root {
                deep_nodes.push((node_id.clone(), *depth));
            }
        }
        
        // Sort by depth (deepest first)
        deep_nodes.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Second pass: find potential new parents
        for (deep_node, _) in deep_nodes {
            let current_parent = match self.parent.get(&deep_node) {
                Some(p) => p.clone(),
                None => continue,
            };
            
            // Find nodes with low depth that are not in the current path to root
            let mut best_candidate = None;
            let mut best_depth = usize::MAX;
            
            // Build path to root to avoid creating cycles
            let mut path_to_root = HashSet::new();
            let mut current = deep_node.clone();
            path_to_root.insert(current.clone());
            
            while let Some(parent) = self.parent.get(&current) {
                path_to_root.insert(parent.clone());
                current = parent.clone();
            }
            
            // Find best candidate
            for (node_id, depth) in &self.depth {
                // Skip nodes in path to root or too deep themselves
                if path_to_root.contains(node_id) || *depth > target_max_depth - 1 {
                    continue;
                }
                
                // Found a better candidate
                if *depth < best_depth {
                    best_depth = *depth;
                    best_candidate = Some(node_id.clone());
                }
            }
            
            // Move node if we found a better parent
            if let Some(new_parent) = best_candidate {
                debug!("Moving node {} from parent {} to {} (depth {} to {})",
                       deep_node, current_parent, new_parent, 
                       self.depth.get(&deep_node).unwrap_or(&0),
                       best_depth + 1);
                
                // Remove from current parent
                if let Some(siblings) = self.children.get_mut(&current_parent) {
                    siblings.remove(&deep_node);
                }
                
                // Update parent pointer
                self.parent.insert(deep_node.clone(), new_parent.clone());
                
                // Add to new parent's children
                if let Some(new_siblings) = self.children.get_mut(&new_parent) {
                    new_siblings.insert(deep_node.clone());
                }
                
                // Update depth for this node and all descendants
                self.update_depth(&deep_node, best_depth + 1);
                
                changes += 1;
            }
        }
        
        // Clear path cache as tree has changed
        if changes > 0 {
            self.path_cache.clear();
            
            // Log improvement
            let metrics_after = self.get_metrics();
            info!("Tree optimization: changed {} nodes, max depth: {} -> {}, avg depth: {:.2} -> {:.2}",
                  changes, metrics_before.max_depth, metrics_after.max_depth,
                  metrics_before.avg_depth, metrics_after.avg_depth);
        }
        
        changes
    }


        // Enhanced clean_message_cache with timestamp tracking
    pub fn clean_message_cache(&mut self, older_than_seconds: u64) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let cutoff = now.saturating_sub(older_than_seconds);

    let count_before = self.message_seen.len();
    self.message_seen.retain(|_, (_, ts)| *ts >= cutoff);
    let removed = count_before - self.message_seen.len();

    if removed > 0 {
        debug!("Cleaned {} old messages from cache", removed);
    }
}

    }
