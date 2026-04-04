import { Routes, Route } from "react-router-dom";
import SubmitPage from "./pages/SubmitPage.tsx";
import RulesPage from "./pages/RulesPage.tsx";
import Nav from "./components/Nav.tsx";

export default function App() {
  return (
    <div className="min-h-screen flex flex-col">
      <Nav />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-6xl">
        <Routes>
          <Route path="/" element={<SubmitPage />} />
<Route path="/rules" element={<RulesPage />} />
        </Routes>
      </main>
    </div>
  );
}
