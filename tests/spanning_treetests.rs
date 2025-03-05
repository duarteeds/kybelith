#[cfg(test)]
mod tests {
    use kybelith::p2p::spanning_tree::SpanningTree;

    #[test]
    fn test_add_remove_node() {
        let mut tree = SpanningTree::new("root".to_string());
        
        // Adicionar alguns nós
        assert!(tree.add_node("child1".to_string(), "root".to_string()));
        assert!(tree.add_node("child2".to_string(), "root".to_string()));
        assert!(tree.add_node("grandchild1".to_string(), "child1".to_string()));
        
        // Verificar profundidades
        assert_eq!(tree.get_depth(&"root".to_string()), Some(0));
        assert_eq!(tree.get_depth(&"child1".to_string()), Some(1));
        assert_eq!(tree.get_depth(&"grandchild1".to_string()), Some(2));
        
        // Remover um nó intermediário
        assert!(tree.remove_node(&"child1".to_string()));
        
        // Verificar se o filho foi reorganizado
        assert_eq!(tree.get_depth(&"grandchild1".to_string()), Some(1));
        assert!(tree.get_children(&"root".to_string()).contains(&"grandchild1".to_string()));
    }

    #[test]
    fn test_forwarding() {
        let mut tree = SpanningTree::new("root".to_string());
        
        // Criar uma pequena árvore
        tree.add_node("child1".to_string(), "root".to_string());
        tree.add_node("child2".to_string(), "root".to_string());
        tree.add_node("grandchild1".to_string(), "child1".to_string());
        
        // Verificar encaminhamento
        assert!(tree.should_forward("msg1", &"root".to_string(), &"child1".to_string()));
        assert!(tree.should_forward("msg1", &"child1".to_string(), &"grandchild1".to_string()));
        
        // Não deve encaminhar para o mesmo nó
        assert!(!tree.should_forward("msg1", &"root".to_string(), &"root".to_string()));
        
        // Não deve encaminhar para nós que não são adjacentes na árvore
        assert!(!tree.should_forward("msg2", &"child1".to_string(), &"child2".to_string()));
        
        // Deve encaminhar da criança para o pai
        assert!(tree.should_forward("msg3", &"child1".to_string(), &"root".to_string()));
    }
}