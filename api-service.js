// api-service.js - This will handle all backend calls
const API_BASE = 'http://localhost:3001/api';

const apiService = {
  // Auth token management
  getToken: () => localStorage.getItem('accessToken'),
  setTokens: (access, refresh) => {
    localStorage.setItem('accessToken', access);
    localStorage.setItem('refreshToken', refresh);
  },
  
  // API call wrapper
  async call(endpoint, options = {}) {
    const token = this.getToken();
    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : '',
        ...options.headers
      }
    });
    
    if (!response.ok) throw new Error(response.statusText);
    return response.json();
  },
  
  // Auth methods
  auth: {
    login: (email, password) => 
      apiService.call('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      }),
    // ... other auth methods
  }
};