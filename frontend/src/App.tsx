import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { HomePage } from './pages/HomePage';
import { ResultsPage } from './pages/ResultsPage';
import { ComparisonPage } from './pages/ComparisonPage';
import { MarathonPage } from './pages/MarathonPage';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/results" element={<ResultsPage />} />
        <Route path="/compare" element={<ComparisonPage />} />
        <Route path="/marathon" element={<MarathonPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;

