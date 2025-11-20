import axios from 'axios';

// API Configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000/api';

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth tokens
apiClient.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for handling errors
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized access
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// API Methods
export const api = {
  // Dashboard Stats
  getStats: () => apiClient.get('/stats'),

  // Scans
  getScans: (params) => apiClient.get('/scans', { params }),
  getScan: (id) => apiClient.get(`/scans/${id}`),
  createScan: (data) => apiClient.post('/scans', data),
  deleteScan: (id) => apiClient.delete(`/scans/${id}`),
  pauseScan: (id) => apiClient.post(`/scans/${id}/pause`),
  resumeScan: (id) => apiClient.post(`/scans/${id}/resume`),

  // Findings
  getFindings: (params) => apiClient.get('/findings', { params }),
  getFinding: (id) => apiClient.get(`/findings/${id}`),
  exportFindings: (params) => apiClient.get('/findings/export', { params }),

  // Providers
  getProviders: () => apiClient.get('/providers'),
  getProvider: (id) => apiClient.get(`/providers/${id}`),
  createProvider: (data) => apiClient.post('/providers', data),
  updateProvider: (id, data) => apiClient.put(`/providers/${id}`, data),
  deleteProvider: (id) => apiClient.delete(`/providers/${id}`),

  // Reports
  getReports: () => apiClient.get('/reports'),
  getReport: (id) => apiClient.get(`/reports/${id}`),
  generateReport: (data) => apiClient.post('/reports', data),
  downloadReport: (id, format) => 
    apiClient.get(`/reports/${id}/download`, {
      params: { format },
      responseType: 'blob',
    }),
};

export default apiClient;
