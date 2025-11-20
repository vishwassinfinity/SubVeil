# Quick Start Guide

## 🚀 Your Frontend is Live!

**Access your application at:** http://localhost:5175/

---

## 📖 Quick Navigation Guide

### 1. Dashboard (/)
- Overview of your security posture
- Key metrics: Total subdomains, vulnerabilities, active scans
- Visual charts for severity distribution
- Recent findings at a glance

### 2. Scans (/scans)
- Click "Add Domain" to start a new scan
- Monitor scan progress in real-time
- View scan history and results
- Control scans (pause/delete)

### 3. Findings (/findings)
- View all detected vulnerabilities
- Click on any finding to expand details
- See DNS records, HTTP evidence, and matched patterns
- Get remediation recommendations
- Filter by severity
- Export findings as JSON

### 4. Providers (/providers)
- View configured service providers
- See detection patterns and fingerprints
- Manage provider settings
- Track detection statistics

### 5. Reports (/reports)
- Generate security reports
- Download in multiple formats
- View report history
- Access comprehensive analysis

---

## 🎨 UI Components Guide

### Severity Badges
- 🔴 **Critical** - Immediate action required
- 🟠 **High** - Urgent attention needed
- 🟡 **Medium** - Should be addressed soon
- 🔵 **Low** - Informational, low priority

### Scan Status
- ✅ **Completed** - Scan finished successfully
- ⏳ **Running** - Scan in progress
- 📅 **Scheduled** - Scan queued for execution
- ❌ **Failed** - Scan encountered errors

---

## 🛠️ Development Workflow

### Making Changes
1. Edit files in `src/` directory
2. Changes auto-reload in browser
3. Check browser console for errors
4. Use React DevTools for debugging

### Adding New Features
1. Create component in `src/components/` or page in `src/pages/`
2. Import and use in App.jsx or other components
3. Add routing if needed in App.jsx
4. Style with Tailwind CSS classes

### Connecting to Backend
1. Update `VITE_API_URL` in `.env` file
2. Use `api` methods from `src/utils/api.js`
3. Replace mock data with API calls
4. Handle loading and error states

---

## 📦 Key Files to Know

| File | Purpose |
|------|---------|
| `src/App.jsx` | Main app with routing |
| `src/components/Layout.jsx` | Navigation and header |
| `src/pages/Dashboard.jsx` | Home page |
| `src/utils/api.js` | API client configuration |
| `src/utils/helpers.js` | Utility functions |
| `tailwind.config.js` | Tailwind customization |

---

## 🔧 Common Tasks

### Add a New Page
```javascript
// 1. Create page component
// src/pages/NewPage.jsx
const NewPage = () => {
  return <div>New Page Content</div>;
};
export default NewPage;

// 2. Add route in App.jsx
import NewPage from './pages/NewPage';
<Route path="/new" element={<NewPage />} />

// 3. Add to navigation in Layout.jsx
{ name: 'New', href: '/new', icon: IconName }
```

### Use API
```javascript
import { api } from '../utils/api';

const fetchData = async () => {
  try {
    const response = await api.getStats();
    setData(response.data);
  } catch (error) {
    console.error('Error:', error);
  }
};
```

### Style with Tailwind
```javascript
<div className="bg-blue-500 text-white p-4 rounded-lg shadow-md">
  Content
</div>
```

---

## ⚡ Performance Tips

- Use React.memo() for expensive components
- Implement pagination for large data sets
- Lazy load routes with React.lazy()
- Optimize images and assets
- Use production build for deployment

---

## 🐛 Debug Mode

Open browser DevTools:
- **Console:** See errors and logs
- **Network:** Monitor API calls
- **React DevTools:** Inspect components
- **Elements:** Check rendered HTML/CSS

---

## 📱 Test Responsiveness

- Resize browser window
- Use DevTools device emulation
- Test on actual mobile devices
- Check all breakpoints work

---

## 🚀 Deploy to Production

```bash
# Build production bundle
npm run build

# Files will be in dist/ folder
# Deploy dist/ folder to:
# - Vercel
# - Netlify
# - AWS S3 + CloudFront
# - Your preferred hosting
```

---

## 💡 Pro Tips

1. **Use Mock Data Initially** - Test UI without backend
2. **Check Mobile First** - Design looks great on all devices
3. **Follow Component Pattern** - Keep components small and reusable
4. **Use TypeScript** - Add type safety for larger projects
5. **Add Tests** - Use Vitest for unit tests
6. **Document Changes** - Update README when adding features
7. **Version Control** - Commit frequently with clear messages

---

## 🎯 Next Development Steps

### Immediate
- [ ] Connect to backend API
- [ ] Replace mock data with real data
- [ ] Add loading spinners
- [ ] Add error boundaries

### Short Term
- [ ] Add authentication
- [ ] Implement WebSocket updates
- [ ] Add advanced filters
- [ ] Create detailed analytics

### Long Term
- [ ] Add dark mode
- [ ] Multi-language support
- [ ] Advanced reporting
- [ ] Email notifications
- [ ] Scheduled scans
- [ ] Webhook integrations

---

## 📞 Need Help?

- Check console for errors
- Review component documentation
- Check API endpoint configuration
- Verify environment variables
- Look at mock data structure

---

## ✨ You're All Set!

Start building your subdomain takeover detection platform!

**Happy Coding!** 🎉
