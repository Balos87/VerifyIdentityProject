import { Link, Outlet, useNavigate } from 'react-router-dom'

const Layout = () => {
  const navigate = useNavigate()

  const handleLogout = () => {
    localStorage.removeItem('isLoggedIn')
    navigate('/')
  }

  return (
    <>
      <header className="bg-gray-800 text-white p-4">
        <nav className="max-w-6xl mx-auto flex justify-between items-center">
          <ul className="flex gap-4">
            <li>
              <Link to="/">Home</Link>
            </li>
            <li>
              <Link to="/account">Account</Link>
            </li>
            <li>
              <Link to="/settings">Settings</Link>
            </li>
          </ul>

          <button
            onClick={handleLogout}
            className="text-sm underline text-red-300 hover:text-red-500"
          >
            Logout
          </button>
        </nav>
      </header>

      <Outlet />

      <footer className="w-full bg-slate-700 text-gray-100 text-center p-4 mt-10">
        <hr className="border-t border-gray-500 mb-2" />
        <p>&copy; 2025 LearnPoint AB</p>
      </footer>
    </>
  )
}

export default Layout
