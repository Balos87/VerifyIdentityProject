import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './App.css'
import AccountPage from './Pages/AccountPage'
import HomePage from './Pages/HomePage'
import Layout from './Pages/Layout'
function App() {

  return (
    <>
      <BrowserRouter>
      <Routes>
          <Route path='/' element={<Layout/>}>
            <Route index element={  <HomePage/>}/>
            <Route path='/account' element={<AccountPage/>}/>
            <Route path='/settings' element/>
        </Route>
        </Routes>
      </BrowserRouter>
    </>
  )
}

export default App
