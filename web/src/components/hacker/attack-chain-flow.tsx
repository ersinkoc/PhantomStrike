import { useCallback, useState, useEffect } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type Connection,
  Panel,
  Handle,
  Position,
  type NodeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Shield, Target, AlertTriangle, CheckCircle2, Play, Circle, type LucideIcon } from 'lucide-react';

// Define the attack node data type
interface AttackNodeData extends Record<string, unknown> {
  type: 'recon' | 'scan' | 'exploit' | 'post' | 'complete';
  label: string;
  status: 'pending' | 'running' | 'complete' | 'failed';
  tool?: string;
  output?: string;
}

const nodeColors: Record<AttackNodeData['type'], string> = {
  recon: '#3b82f6',
  scan: '#f59e0b',
  exploit: '#ef4444',
  post: '#8b5cf6',
  complete: '#10b981',
};

const nodeIcons: Record<AttackNodeData['type'], LucideIcon> = {
  recon: Target,
  scan: Shield,
  exploit: AlertTriangle,
  post: Play,
  complete: CheckCircle2,
};

// Custom node component - using any for data to satisfy React Flow
function AttackNodeComponent({ data, selected }: { data: Record<string, unknown>; selected?: boolean }) {
  const nodeData = data as unknown as AttackNodeData;
  const Icon = nodeIcons[nodeData.type] || Circle;
  const color = nodeColors[nodeData.type] || '#6b7280';

  return (
    <div
      className={`relative px-4 py-3 rounded-lg border-2 transition-all ${
        selected ? 'ring-2 ring-white/50' : ''
      } ${
        nodeData.status === 'running'
          ? 'animate-pulse'
          : ''
      }`}
      style={{
        backgroundColor: `${color}20`,
        borderColor: color,
        minWidth: 180,
      }}
    >
      <Handle type="target" position={Position.Top} className="w-3 h-3" style={{ background: color }} />

      <div className="flex items-center gap-3">
        <div
          className="w-10 h-10 rounded-full flex items-center justify-center"
          style={{ backgroundColor: `${color}40` }}
        >
          <Icon className="w-5 h-5" style={{ color }} />
        </div>
        <div className="flex-1">
          <div className="text-white font-medium text-sm">{nodeData.label}</div>
          {nodeData.tool && (
            <div className="text-xs text-gray-400">{nodeData.tool}</div>
          )}
        </div>
      </div>

      <div className="mt-2 flex items-center gap-2">
        <div
          className={`w-2 h-2 rounded-full ${
            nodeData.status === 'complete'
              ? 'bg-green-500'
              : nodeData.status === 'running'
                ? 'bg-yellow-500 animate-pulse'
                : nodeData.status === 'failed'
                  ? 'bg-red-500'
                  : 'bg-gray-500'
          }`}
        />
        <span className="text-xs text-gray-400 capitalize">{nodeData.status}</span>
      </div>

      {nodeData.output && (
        <div className="mt-2 p-2 bg-black/50 rounded text-xs font-mono text-green-400 max-h-20 overflow-y-auto">
          {nodeData.output.slice(0, 100)}...
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="w-3 h-3" style={{ background: color }} />
    </div>
  );
}

// Node types for ReactFlow
const nodeTypes: NodeTypes = {
  attack: AttackNodeComponent,
};

interface AttackChainData {
  nodes: Array<{
    id: string;
    type: 'recon' | 'scan' | 'exploit' | 'post' | 'complete';
    label: string;
    status: 'pending' | 'running' | 'complete' | 'failed';
    tool?: string;
    output?: string;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
  }>;
}

interface AttackChainFlowProps {
  missionId?: string;
  data?: AttackChainData;
}

export function AttackChainFlow({ data: initialData }: AttackChainFlowProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<AttackNodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNode, setSelectedNode] = useState<Node<AttackNodeData> | null>(null);

  useEffect(() => {
    if (initialData) {
      const flowNodes: Node<AttackNodeData>[] = initialData.nodes.map((node, index) => ({
        id: node.id,
        type: 'attack',
        position: { x: 250 + (index % 3) * 300, y: 100 + Math.floor(index / 3) * 200 },
        data: node,
      }));

      const flowEdges: Edge[] = initialData.edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: true,
        style: { stroke: '#10b981', strokeWidth: 2 },
        type: 'smoothstep',
      }));

      setNodes(flowNodes);
      setEdges(flowEdges);
    } else {
      // Default demo data
      setNodes([
        {
          id: '1',
          type: 'attack',
          position: { x: 250, y: 100 },
          data: { label: 'Subdomain Enum', type: 'recon', status: 'complete', tool: 'amass' },
        },
        {
          id: '2',
          type: 'attack',
          position: { x: 550, y: 100 },
          data: { label: 'Port Scan', type: 'scan', status: 'complete', tool: 'nmap' },
        },
        {
          id: '3',
          type: 'attack',
          position: { x: 850, y: 100 },
          data: { label: 'Web Probe', type: 'scan', status: 'running', tool: 'httpx' },
        },
        {
          id: '4',
          type: 'attack',
          position: { x: 400, y: 300 },
          data: { label: 'Vuln Scan', type: 'exploit', status: 'pending', tool: 'nuclei' },
        },
        {
          id: '5',
          type: 'attack',
          position: { x: 700, y: 300 },
          data: { label: 'SQL Injection', type: 'exploit', status: 'pending', tool: 'sqlmap' },
        },
        {
          id: '6',
          type: 'attack',
          position: { x: 550, y: 500 },
          data: { label: 'Report', type: 'complete', status: 'pending' },
        },
      ]);

      setEdges([
        { id: 'e1-2', source: '1', target: '2', animated: true, style: { stroke: '#10b981' }, type: 'smoothstep' },
        { id: 'e2-3', source: '2', target: '3', animated: true, style: { stroke: '#10b981' }, type: 'smoothstep' },
        { id: 'e3-4', source: '3', target: '4', animated: true, style: { stroke: '#f59e0b' }, type: 'smoothstep' },
        { id: 'e3-5', source: '3', target: '5', animated: true, style: { stroke: '#f59e0b' }, type: 'smoothstep' },
        { id: 'e4-6', source: '4', target: '6', animated: true, style: { stroke: '#8b5cf6' }, type: 'smoothstep' },
        { id: 'e5-6', source: '5', target: '6', animated: true, style: { stroke: '#8b5cf6' }, type: 'smoothstep' },
      ]);
    }
  }, [initialData, setNodes, setEdges]);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  const getNodeColor = (node: Node): string => {
    const nodeType = (node.data as AttackNodeData | undefined)?.type;
    return nodeType ? nodeColors[nodeType] : '#6b7280';
  };

  return (
    <div className="h-[600px] w-full bg-black/50 border border-green-500/30 rounded-lg overflow-hidden">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodeTypes={nodeTypes}
        onNodeClick={(_, node) => setSelectedNode(node)}
        fitView
        attributionPosition="bottom-left"
      >
        <Background color="#10b981" gap={16} size={1} />
        <Controls className="bg-black/80 border-green-500/30" />
        <MiniMap
          nodeColor={getNodeColor}
          maskColor="rgba(0,0,0,0.8)"
          className="bg-black/80 border-green-500/30"
        />

        <Panel position="top-right" className="bg-black/80 border border-green-500/30 rounded-lg p-4 m-4">
          <h3 className="text-green-400 font-mono font-bold mb-2">Attack Chain</h3>
          <div className="space-y-1 text-xs">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ background: nodeColors.recon }} />
              <span className="text-gray-300">Reconnaissance</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ background: nodeColors.scan }} />
              <span className="text-gray-300">Scanning</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ background: nodeColors.exploit }} />
              <span className="text-gray-300">Exploitation</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ background: nodeColors.post }} />
              <span className="text-gray-300">Post-Exploitation</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ background: nodeColors.complete }} />
              <span className="text-gray-300">Complete</span>
            </div>
          </div>
        </Panel>

        {selectedNode && (
          <Panel position="bottom-right" className="bg-black/90 border border-green-500/30 rounded-lg p-4 m-4 max-w-sm">
            <h4 className="text-green-400 font-mono font-bold mb-2">{String((selectedNode.data as AttackNodeData).label)}</h4>
            <div className="space-y-1 text-sm text-gray-300">
              <p>Status: <span className="text-green-400">{String((selectedNode.data as AttackNodeData).status)}</span></p>
              {(selectedNode.data as AttackNodeData).tool && (
                <p>Tool: <span className="text-green-400">{String((selectedNode.data as AttackNodeData).tool)}</span></p>
              )}
              <p>Type: <span className="text-green-400 capitalize">{String((selectedNode.data as AttackNodeData).type)}</span></p>
            </div>
          </Panel>
        )}
      </ReactFlow>
    </div>
  );
}
