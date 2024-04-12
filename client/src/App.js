import React from 'react';
import {BrowserRouter, Routes, Route} from "react-router-dom";
import LoginComponent from './components/Login.tsx'
import "./App.css"
function App() {
  return (
    <div className="App">
      <BrowserRouter>
          <Routes>
            <Route path="/" element={<LoginComponent/>}/>
          </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;