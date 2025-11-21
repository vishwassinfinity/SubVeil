import { useState, useEffect } from 'react';
import { Plus, Search, Play, Pause, Trash2, Calendar, Globe } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import { api } from '../utils/api';

const Scans = () => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 3000); // Refresh every 3 seconds for real-time updates
    return () => clearInterval(interval);
  }, []);

  const fetchScans = async () => {
    try {
      const response = await api.getScans();
      setScans(response.data);
      setLoading(false);
      setError(null);
    } catch (err) {
      console.error('Error fetching scans:', err);
      setError('Failed to load scans');
      setLoading(false);
    }
  };

  const handleAddDomain = async (e) => {
    e.preventDefault();
    if (newDomain.trim()) {
      try {
        await api.createScan({ domain: newDomain.trim() });
        setNewDomain('');
        setShowAddModal(false);
        fetchScans(); // Refresh the list
      } catch (err) {
        console.error('Error creating scan:', err);
        alert('Failed to create scan. Please try again.');
      }
    }
  };

  const getStatusBadge = (status) => {
    const variants = {
      completed: 'success',
      running: 'info',
      scheduled: 'default',
      failed: 'critical',
      paused: 'medium',
    };
    return <Badge variant={variants[status]}>{status.toUpperCase()}</Badge>;
  };

  const handleDeleteScan = async (id) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      try {
        await api.deleteScan(id);
        fetchScans();
      } catch (err) {
        console.error('Error deleting scan:', err);
        alert('Failed to delete scan');
      }
    }
  };

  const handlePauseScan = async (id) => {
    try {
      await api.pauseScan(id);
      fetchScans();
    } catch (err) {
      console.error('Error pausing scan:', err);
      alert('Failed to pause scan');
    }
  };

  const handleResumeScan = async (id) => {
    try {
      await api.resumeScan(id);
      fetchScans();
    } catch (err) {
      console.error('Error resuming scan:', err);
      alert('Failed to resume scan');
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleString();
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
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              <span className="ml-3 text-gray-600">Loading scans...</span>
            </div>
          ) : error ? (
            <div className="flex items-center justify-center py-12">
              <p className="text-red-600">{error}</p>
            </div>
          ) : scans.length === 0 ? (
            <div className="text-center py-12">
              <Globe className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No scans yet</h3>
              <p className="text-sm text-gray-500 mb-4">Get started by adding a domain to scan</p>
              <Button onClick={() => setShowAddModal(true)}>
                <Plus className="h-4 w-4 mr-2 inline" />
                Add Domain
              </Button>
            </div>
          ) : (
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
                      {formatDate(scan.startTime)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.subdomainsFound ?? '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {scan.vulnerableCount !== null && scan.vulnerableCount !== undefined ? (
                        <span className={`text-sm font-medium ${
                          scan.vulnerableCount > 0 ? 'text-red-600' : 'text-green-600'
                        }`}>
                          {scan.vulnerableCount}
                        </span>
                      ) : (
                        <span className="text-sm text-gray-500">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
                      {scan.status === 'running' && (
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            handlePauseScan(scan.id);
                          }}
                          className="text-orange-600 hover:text-orange-900"
                          title="Pause scan"
                        >
                          <Pause className="h-4 w-4 inline" />
                        </button>
                      )}
                      {scan.status === 'paused' && (
                        <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleResumeScan(scan.id);
                          }}
                          className="text-green-600 hover:text-green-900"
                          title="Resume scan"
                        >
                          <Play className="h-4 w-4 inline" />
                        </button>
                      )}
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteScan(scan.id);
                        }}
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
          )}
        </CardContent>
      </Card>      {/* Add Domain Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg max-w-md w-full p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Add New Domain
            </h3>
            <form onSubmit={handleAddDomain}>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Domain Name
                </label>
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="example.com"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  required
                />
                <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
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
