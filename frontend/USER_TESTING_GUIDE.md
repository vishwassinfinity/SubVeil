# SubVeil Frontend - User Testing Guide

## 🎯 Quick Testing Steps

### Prerequisites
The development server should be running at http://localhost:5173/

---

## Test 1: Dashboard ✅
**What to verify:**
- All 8 stat cards display numbers
- 4 charts render with data
- Domain activity section shows progress bars
- Recent findings table has 3 rows
- Navigation links work

**Steps:**
1. Open http://localhost:5173/
2. ✅ See 8 stat cards with values
3. ✅ See pie chart, bar chart, area chart, line chart
4. ✅ See domain activity with progress bars
5. ✅ See recent findings table

---

## Test 2: Add a Domain Scan ✅
**What to verify:**
- Modal opens
- Form validation works
- New scan appears in list

**Steps:**
1. Click "Scans" in navigation
2. Click "Add Domain" button
3. ✅ Modal appears
4. Enter `testdomain.com`
5. Click "Add Domain"
6. ✅ Modal closes
7. ✅ New scan appears at top of table

---

## Test 3: Scan Controls ✅
**What to verify:**
- Start, pause, resume buttons work
- Status badges update
- Delete confirmation works

**Steps:**
1. Find a "Scheduled" scan
2. Click ▶️ (play) button
3. ✅ Status changes to "Running"
4. Click ⏸️ (pause) button
5. ✅ Status changes to "Paused"
6. Click ▶️ (play) button again
7. ✅ Status changes to "Running"
8. Click 🗑️ (delete) button
9. ✅ Confirmation dialog appears
10. Click "OK"
11. ✅ Scan removed from list

---

## Test 4: View Finding Details ✅
**What to verify:**
- Findings expand/collapse
- Details show evidence
- External link works

**Steps:**
1. Click "Findings" in navigation
2. Click on first finding row
3. ✅ Expands to show DNS evidence
4. ✅ Shows HTTP response
5. ✅ Shows remediation steps
6. Click row again
7. ✅ Collapses back
8. Click 🔗 external link icon
9. ✅ Opens subdomain in new tab

---

## Test 5: Filter Findings ✅
**What to verify:**
- Dropdown filter works
- Count updates
- Empty state shows when no matches

**Steps:**
1. On Findings page
2. Click severity dropdown
3. Select "Critical"
4. ✅ Shows only critical findings
5. ✅ Count shows "1 of 3" or similar
6. Select "All"
7. ✅ Shows all findings again

---

## Test 6: Export Findings ✅
**What to verify:**
- Export button works
- File downloads
- Contains data

**Steps:**
1. On Findings page
2. Click "Export" button
3. ✅ File downloads
4. ✅ Filename includes date: `findings-2024-11-20.json`
5. Open downloaded file
6. ✅ Contains JSON data with all findings

---

## Test 7: Toggle Provider Status ✅
**What to verify:**
- Provider status toggles
- Badge color changes
- Stats update

**Steps:**
1. Click "Providers" in navigation
2. Find "Netlify" provider (Inactive)
3. Click on "Inactive" badge
4. ✅ Badge changes to "Active" (green)
5. Click again
6. ✅ Badge changes back to "Inactive" (gray)
7. ✅ Active provider count updates

---

## Test 8: Delete Provider ✅
**What to verify:**
- Confirmation dialog appears
- Provider removed from list
- Stats update

**Steps:**
1. On Providers page
2. Find any provider
3. Click 🗑️ (delete) button
4. ✅ Confirmation dialog appears
5. Click "OK"
6. ✅ Provider removed from grid
7. ✅ Total provider count decreases

---

## Test 9: Generate Report ✅
**What to verify:**
- Report type cards are clickable
- Modal opens with pre-filled type
- Form submission works
- New report appears

**Steps:**
1. Click "Reports" in navigation
2. Click "Full Scan Report" card
3. ✅ Modal opens with "Full Scan" pre-selected
4. Enter title: "Test Security Report"
5. Select format: "PDF"
6. Click "Generate Report"
7. ✅ Modal closes
8. ✅ New report appears at top of table
9. ✅ Has today's date

**Alternative:**
1. Click "Generate Report" button instead
2. ✅ Same modal functionality

---

## Test 10: Download Report ✅
**What to verify:**
- Download button works
- File is created
- Proper filename

**Steps:**
1. On Reports page
2. Find any report
3. Click "Download" button
4. ✅ File downloads
5. ✅ Filename matches report title
6. Open file
7. ✅ Contains report data

---

## Test 11: Dark/Light Theme ✅
**What to verify:**
- Theme toggle works
- All pages support both themes
- Theme persists after refresh

**Steps:**
1. Look for 🌙 (moon) icon in header
2. Click it
3. ✅ Theme switches to dark mode
4. ✅ Icon changes to ☀️ (sun)
5. Navigate to each page
6. ✅ All pages are dark themed
7. Refresh browser (F5)
8. ✅ Dark theme persists
9. Click ☀️ icon
10. ✅ Switches back to light mode

---

## Test 12: Mobile Menu ✅
**What to verify:**
- Hamburger menu appears on small screens
- Menu opens/closes
- All links work
- Theme toggle in mobile menu

**Steps:**
1. Resize browser to mobile width (< 768px) OR open DevTools mobile view
2. ✅ See hamburger menu (☰)
3. Click hamburger menu
4. ✅ Menu panel slides in
5. ✅ See all navigation links
6. ✅ See theme toggle option
7. Click "Scans"
8. ✅ Menu closes
9. ✅ Navigates to Scans page

---

## Test 13: Responsive Design ✅
**What to verify:**
- Layout adapts to screen size
- No horizontal scrolling
- Content readable at all sizes

**Steps:**
1. Open browser DevTools (F12)
2. Toggle device toolbar (Ctrl+Shift+M)
3. Try different devices:
   - iPhone SE (375px)
   - iPad (768px)
   - Laptop (1024px)
   - Desktop (1440px)
4. ✅ Layout adjusts appropriately
5. ✅ All content accessible
6. ✅ No broken layouts

---

## Test 14: Navigation & Routing ✅
**What to verify:**
- All pages load
- URL changes
- Active state highlights current page

**Steps:**
1. Click each navigation link:
   - Dashboard
   - Scans
   - Findings
   - Providers
   - Reports
2. ✅ Each page loads correctly
3. ✅ URL updates (e.g., `/scans`, `/findings`)
4. ✅ Active page has blue background in nav
5. Try browser back/forward buttons
6. ✅ Navigation works correctly

---

## Test 15: Charts & Visualizations ✅
**What to verify:**
- All charts render
- Tooltips work on hover
- Charts are responsive

**Steps:**
1. Go to Dashboard
2. Hover over pie chart
3. ✅ Tooltip shows percentage
4. Hover over bar chart
5. ✅ Tooltip shows count
6. Hover over line chart
7. ✅ Tooltip shows values
8. Resize window
9. ✅ Charts resize proportionally

---

## 🎉 All Tests Passed?

If you can complete all 15 tests successfully, congratulations! Every feature in the SubVeil frontend is working perfectly.

### Summary Checklist
- [ ] Dashboard displays all data
- [ ] Can add domain scans
- [ ] Can start/pause/resume/delete scans
- [ ] Can view finding details
- [ ] Can filter findings
- [ ] Can export findings
- [ ] Can toggle provider status
- [ ] Can delete providers
- [ ] Can generate reports
- [ ] Can download reports
- [ ] Theme toggle works
- [ ] Mobile menu works
- [ ] Responsive on all screen sizes
- [ ] Navigation works
- [ ] Charts render correctly

---

## 🐛 Found an Issue?

If any test fails, check:
1. Is the dev server running? (`npm run dev`)
2. Is the browser console showing errors? (F12)
3. Did you refresh the page after theme changes?
4. Is JavaScript enabled in your browser?

All features should work perfectly - they've been thoroughly tested and verified! ✨
