import { Link, Outlet } from 'react-router-dom'

const Layout = () => {
  return (
    <>
    <header>
    <nav>
        <ul>
          <li>
            <Link to="/">Home</Link>
          </li>
            <li>
            <Link to="/account">Account</Link>
          </li>
        </ul>
        </nav>  
    </header>

      <Outlet />

    <footer>
      <hr className='br-footer'/>
      <p>&copy; 2025 LearnPoint AB </p>
    </footer>
    </>
  )
}

export default Layout
