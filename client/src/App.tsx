import React from 'react';
import {BrowserRouter, Routes, Route} from "react-router-dom";
import LoginComponent from './components/Login.tsx'
import RegistrationComponent from './components/Register.tsx';
import "./App.css"
import HomeComponent from './components/Home.tsx';
function App() {
  return (
    <div className="App">
      <BrowserRouter>
          <Routes>
            <Route path="/" element={<HomeComponent/>}/>
            <Route path="/login" element={<LoginComponent/>}/>
            <Route path="/register" element={<RegistrationComponent />} />
          </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;