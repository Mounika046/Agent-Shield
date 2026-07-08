import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './AppShell'
import { DashboardPage } from '../features/dashboard/DashboardPage'
import { AssetClassesPage } from '../features/assetClasses/AssetClassesPage'
import { AssetClassDetailPage } from '../features/assetClasses/AssetClassDetailPage'
import { AssetDetailPage } from '../features/assets/AssetDetailPage'
import { ScanCenterPage } from '../features/scanCenter/ScanCenterPage'
import { RunsPage } from '../features/runs/RunsPage'

export const AppRoutes = () => (
  <Routes>
    <Route element={<AppShell />}>
      <Route path="/" element={<DashboardPage />} />
      <Route path="/asset-classes" element={<AssetClassesPage />} />
      <Route path="/asset-classes/:classId" element={<AssetClassDetailPage />} />
      <Route path="/assets/:assetId" element={<AssetDetailPage />} />
      <Route path="/scan-center" element={<ScanCenterPage />} />
      <Route path="/runs" element={<RunsPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes>
)
