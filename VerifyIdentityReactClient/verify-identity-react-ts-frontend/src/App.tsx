import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './Pages/Layout'
import HomePage from './Pages/HomePage'
import AccountPage from './Pages/AccountPage'
import ProtectedRoute from './components/ProtectedRoute'
import Settings from './Pages/Settings'

function App() {
  return (
    <BrowserRouter>
      <Routes>
      <Route path="/" element={<Layout />}>
          <Route index element={<HomePage />} />

          {/* 🛡️ This must be wrapped! */}
          <Route
            path="account"
            element={
              <ProtectedRoute>
                <AccountPage />
              </ProtectedRoute>
            }
          />

          {/* 🛡️ Protect Settings too */}
          <Route
            path="settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
