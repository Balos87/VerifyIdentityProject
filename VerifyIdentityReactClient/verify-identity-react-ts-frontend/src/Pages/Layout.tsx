import { Link, Outlet } from 'react-router-dom'
import { useState } from "react";

const Layout = () => {
  const[isloggedIn, setIsLoggedIn] = useState(false);
  return (
    <>
    <header>
    <nav>
        <ul>
          {isloggedIn &&(
            <>
              <li>
                <Link to="/">Home</Link>
              </li>
              <li>
                <Link to="/account">Account</Link>
              </li>
              <li>
                <Link to="/settings">Settings</Link>
              </li>
            </>
          )}
        </ul>
      </nav>  
    </header>

      <Outlet />

    <footer className='w-full bg-slate-700 text-gray-100 text-center p-4 absolute bottom-0 left-0'>
      <hr className='border-t border-gray-500'/>
      <p>&copy; 2025 LearnPoint AB </p>
    </footer>
    </>
  )
}

export default Layout
