import { useState } from 'react';
import { Server, Plus, Edit, Trash2, Shield } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const Providers = () => {
  const [providers, setProviders] = useState([
    {
      id: 1,
      name: 'GitHub Pages',
      cname: '*.github.io',
      fingerprints: [
        'There isn\'t a GitHub Pages site here.',
        'For root URLs (like http://example.com/) you must provide an index.html file',
      ],
      httpCodes: [404],
      active: true,
      detectionsCount: 8,
    },
    {
      id: 2,
      name: 'AWS S3',
      cname: '*.s3.amazonaws.com',
      fingerprints: [
        'NoSuchBucket',
        'The specified bucket does not exist',
      ],
      httpCodes: [404, 403],
      active: true,
      detectionsCount: 6,
    },
    {
      id: 3,
      name: 'Heroku',
      cname: '*.herokuapp.com',
      fingerprints: [
        'No such app',
        'There is no app configured at that hostname',
      ],
      httpCodes: [404, 410],
      active: true,
      detectionsCount: 4,
    },
    {
      id: 4,
      name: 'Azure',
      cname: '*.azurewebsites.net',
      fingerprints: [
        'Error 404 - Web app not found',
        'The resource you are looking for has been removed',
      ],
      httpCodes: [404],
      active: true,
      detectionsCount: 3,
    },
    {
      id: 5,
      name: 'Vercel',
      cname: '*.vercel.app',
      fingerprints: [
        'The deployment could not be found on Vercel',
        '404: NOT_FOUND',
      ],
      httpCodes: [404],
      active: true,
      detectionsCount: 2,
    },
    {
      id: 6,
      name: 'Netlify',
      cname: '*.netlify.app',
      fingerprints: [
        'Not Found - Request ID:',
        'Page not found',
      ],
      httpCodes: [404],
      active: false,
      detectionsCount: 0,
    },
  ]);

  const handleToggleActive = (id) => {
    setProviders(providers.map(p => 
      p.id === id ? { ...p, active: !p.active } : p
    ));
  };

  const handleDeleteProvider = (id) => {
    if (window.confirm('Are you sure you want to delete this provider?')) {
      setProviders(providers.filter(p => p.id !== id));
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Provider Configuration</h2>
          <p className="mt-1 text-sm text-gray-500">
            Manage provider fingerprints and detection patterns
          </p>
        </div>
        <Button onClick={() => alert('Add Provider functionality - Coming soon!')}>
          <Plus className="h-4 w-4 mr-2 inline" />
          Add Provider
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardContent className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Providers</p>
              <p className="mt-2 text-3xl font-bold text-gray-900">{providers.length}</p>
            </div>
            <Server className="h-10 w-10 text-blue-600" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Providers</p>
              <p className="mt-2 text-3xl font-bold text-gray-900">
                {providers.filter(p => p.active).length}
              </p>
            </div>
            <Shield className="h-10 w-10 text-green-600" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Detections</p>
              <p className="mt-2 text-3xl font-bold text-gray-900">
                {providers.reduce((sum, p) => sum + p.detectionsCount, 0)}
              </p>
            </div>
            <Server className="h-10 w-10 text-orange-600" />
          </CardContent>
        </Card>
      </div>

      {/* Providers List */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {providers.map((provider) => (
          <Card key={provider.id}>
            <CardContent>
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-3">
                    <h3 className="text-lg font-semibold text-gray-900">
                      {provider.name}
                    </h3>
                    <button
                      onClick={() => handleToggleActive(provider.id)}
                      title={provider.active ? 'Deactivate provider' : 'Activate provider'}
                    >
                      <Badge variant={provider.active ? 'success' : 'default'}>
                        {provider.active ? 'Active' : 'Inactive'}
                      </Badge>
                    </button>
                    <Badge variant="info">
                      {provider.detectionsCount} detections
                    </Badge>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <h4 className="text-sm font-medium text-gray-700 mb-2">
                        CNAME Pattern
                      </h4>
                      <p className="font-mono text-sm text-blue-600 bg-blue-50 px-3 py-2 rounded">
                        {provider.cname}
                      </p>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium text-gray-700 mb-2">
                        HTTP Status Codes
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {provider.httpCodes.map((code, index) => (
                          <Badge key={index} variant="default">
                            {code}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium text-gray-700 mb-2">
                        Detection Fingerprints
                      </h4>
                      <div className="space-y-1">
                        {provider.fingerprints.map((fingerprint, index) => (
                          <div
                            key={index}
                            className="text-sm text-gray-600 bg-gray-50 px-3 py-2 rounded"
                          >
                            "{fingerprint}"
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex space-x-2 ml-4">
                  <button 
                    className="p-2 text-blue-600 hover:bg-blue-50 rounded"
                    title="Edit provider"
                    onClick={() => alert('Edit functionality - Coming soon!')}
                  >
                    <Edit className="h-4 w-4" />
                  </button>
                  <button 
                    onClick={() => handleDeleteProvider(provider.id)}
                    className="p-2 text-red-600 hover:bg-red-50 rounded"
                    title="Delete provider"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default Providers;
