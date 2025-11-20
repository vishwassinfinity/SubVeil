import { useState } from 'react';
import { Plus, Search, Play, Pause, Trash2, Calendar, Globe } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const Scans = () => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [scans, setScans] = useState([
    {
      id: 1,
      domain: 'example.com',
      status: 'completed',
      startTime: '2024-11-20 08:00',
      endTime: '2024-11-20 08:15',
      subdomainsFound: 1247,
      vulnerabilitiesFound: 23,
    },
    {
      id: 2,
      domain: 'testdomain.com',
      status: 'running',
      startTime: '2024-11-20 10:30',
      endTime: null,
      subdomainsFound: 543,
      vulnerabilitiesFound: 8,
    },
    {
      id: 3,
      domain: 'company.org',
      status: 'scheduled',
      startTime: '2024-11-21 00:00',
      endTime: null,
      subdomainsFound: null,
      vulnerabilitiesFound: null,
    },
  ]);

  const handleAddDomain = (e) => {
    e.preventDefault();
    if (newDomain.trim()) {
      const newScan = {
        id: scans.length + 1,
        domain: newDomain,
        status: 'scheduled',
        startTime: new Date().toISOString().slice(0, 16).replace('T', ' '),
        endTime: null,
        subdomainsFound: null,
        vulnerabilitiesFound: null,
      };
      setScans([newScan, ...scans]);
      setNewDomain('');
      setShowAddModal(false);
    }
  };

  const getStatusBadge = (status) => {
    const variants = {
      completed: 'success',
      running: 'info',
      scheduled: 'default',
      failed: 'critical',
    };
    return <Badge variant={variants[status]}>{status.toUpperCase()}</Badge>;
  };

  const handleDeleteScan = (id) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      setScans(scans.filter(scan => scan.id !== id));
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Scan Management</h2>
          <p className="mt-1 text-sm text-gray-500">
            Manage and monitor subdomain scans
          </p>
        </div>
        <Button onClick={() => setShowAddModal(true)}>
          <Plus className="h-4 w-4 mr-2 inline" />
          Add Domain
        </Button>
      </div>

      {/* Scans List */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Domain
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Start Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Subdomains
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Vulnerabilities
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <Globe className="h-4 w-4 text-gray-400 mr-2" />
                        <span className="text-sm font-medium text-gray-900">
                          {scan.domain}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getStatusBadge(scan.status)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.startTime}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.subdomainsFound ?? '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {scan.vulnerabilitiesFound !== null ? (
                        <span className={`text-sm font-medium ${
                          scan.vulnerabilitiesFound > 0 ? 'text-red-600' : 'text-green-600'
                        }`}>
                          {scan.vulnerabilitiesFound}
                        </span>
                      ) : (
                        <span className="text-sm text-gray-500">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
                      {scan.status === 'running' && (
                        <button className="text-orange-600 hover:text-orange-900">
                          <Pause className="h-4 w-4 inline" />
                        </button>
                      )}
                      {scan.status === 'scheduled' && (
                        <button className="text-blue-600 hover:text-blue-900">
                          <Play className="h-4 w-4 inline" />
                        </button>
                      )}
                      <button 
                        onClick={() => handleDeleteScan(scan.id)}
                        className="text-red-600 hover:text-red-900"
                      >
                        <Trash2 className="h-4 w-4 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Add Domain Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg max-w-md w-full p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Add New Domain
            </h3>
            <form onSubmit={handleAddDomain}>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Domain Name
                </label>
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
                <p className="mt-2 text-sm text-gray-500">
                  Enter the root domain to scan for subdomains
                </p>
              </div>
              <div className="flex justify-end space-x-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setShowAddModal(false);
                    setNewDomain('');
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit">
                  Add Domain
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Scans;
