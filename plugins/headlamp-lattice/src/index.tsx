import { registerRoute, registerSidebarEntry } from '@kinvolk/headlamp-plugin/lib';
import LatticeServiceList from './components/LatticeServiceList';
import LatticeServiceDetail from './components/LatticeServiceDetail';

// Sidebar: top-level "Lattice" group with "Services" sub-item
registerSidebarEntry({
  parent: null,
  name: 'Lattice',
  label: 'Lattice',
  url: '/lattice/services',
  icon: 'mdi:hexagon-multiple',
  useClusterURL: true,
  sidebar: 'IN-CLUSTER',
});

registerSidebarEntry({
  parent: 'Lattice',
  name: 'LatticeServices',
  label: 'Services',
  url: '/lattice/services',
  useClusterURL: true,
  sidebar: 'IN-CLUSTER',
});

// Routes
registerRoute({
  path: '/lattice/services',
  sidebar: {
    item: 'LatticeServices',
    sidebar: 'IN-CLUSTER',
  },
  name: 'LatticeServices',
  exact: true,
  useClusterURL: true,
  component: () => <LatticeServiceList />,
});

registerRoute({
  path: '/lattice/services/:namespace/:name',
  sidebar: {
    item: 'LatticeServices',
    sidebar: 'IN-CLUSTER',
  },
  name: 'LatticeServiceDetail',
  exact: true,
  useClusterURL: true,
  component: () => <LatticeServiceDetail />,
});
