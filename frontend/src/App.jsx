import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, RequireAuth } from './auth'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Compare from './pages/Compare'
import Targets from './pages/Targets'
import Assets from './pages/Assets'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 10_000 },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<RequireAuth><Dashboard /></RequireAuth>} />
            <Route path="/scans" element={<RequireAuth><Scans /></RequireAuth>} />
            <Route path="/scans/:id" element={<RequireAuth><ScanDetail /></RequireAuth>} />
            <Route path="/compare" element={<RequireAuth><Compare /></RequireAuth>} />
            <Route path="/targets" element={<RequireAuth><Targets /></RequireAuth>} />
            <Route path="/assets" element={<RequireAuth><Assets /></RequireAuth>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}