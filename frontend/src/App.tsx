import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import OverviewPage from "./pages/OverviewPage";
import ProjectsPage from "./pages/ProjectsPage";
import FunctionsPage from "./pages/FunctionsPage";
import BuildPage from "./pages/BuildPage";
import LiveDashboardPage from "./pages/LiveDashboardPage";
import KGExplorerPage from "./pages/KGExplorerPage";
import AgentAuditPage from "./pages/AgentAuditPage";
import ValidationPage from "./pages/ValidationPage";
import EvaluationPage from "./pages/EvaluationPage";
import PackagingPage from "./pages/PackagingPage";
import SettingsPage from "./pages/SettingsPage";
import LLMProvidersPage from "./pages/LLMProvidersPage";
import KGBuilderPage from "./pages/KGBuilderPage";
import ResearchRunPage from "./pages/ResearchRunPage";
import ResearchRunsPage from "./pages/ResearchRunsPage";
import AgentTracePage from "./pages/AgentTracePage";
import AgentFlowPage from "./pages/AgentFlowPage";
import KGQueryFlowPage from "./pages/KGQueryFlowPage";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/projects" element={<ProjectsPage />} />
        <Route path="/functions" element={<FunctionsPage />} />
        <Route path="/build" element={<BuildPage />} />
        <Route path="/live" element={<LiveDashboardPage />} />
        <Route path="/live/:jobId" element={<LiveDashboardPage />} />
        <Route path="/kg" element={<KGExplorerPage />} />
        <Route path="/kg/:kgId" element={<KGExplorerPage />} />
        <Route path="/audit" element={<AgentAuditPage />} />
        <Route path="/research" element={<ResearchRunPage />} />
        <Route path="/research/runs" element={<ResearchRunsPage />} />
        <Route path="/research/live/:jobId" element={<LiveDashboardPage />} />
        <Route path="/research/trace/:runId/:sampleId" element={<AgentTracePage />} />
        <Route path="/research/flow" element={<AgentFlowPage />} />
        <Route path="/research/flow/:runId/:sampleId" element={<AgentFlowPage />} />
        <Route path="/research/kg/:runId/:sampleId" element={<KGQueryFlowPage />} />
        <Route path="/validation" element={<ValidationPage />} />
        <Route path="/evaluation" element={<EvaluationPage />} />
        <Route path="/packaging" element={<PackagingPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/llm-providers" element={<LLMProvidersPage />} />
        <Route path="/kg-builder" element={<KGBuilderPage />} />
      </Routes>
    </Layout>
  );
}
