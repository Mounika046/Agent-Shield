import { BrowserRouter } from 'react-router-dom'
import { AppStoreProvider } from './app/AppProvider'
import { AppRoutes } from './app/routes'

function App() {
  return (
    <AppStoreProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AppStoreProvider>
  )
}

export default App
