// RegistrationComponent.js
import React, { useState } from 'react';
import axios from '../utils/AxiosWithCredentials.ts';
import { Link } from 'react-router-dom';
import { hostname } from '../utils/utils.ts';
const RegistrationComponent = () => {
  const [feedback, setFeedback] = useState('');
  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${hostname}/register`, 
      {
        username:e.target.elements.usernameInput.value,
        password:e.target.elements.passwordInput.value
      }
      );
      console.log(response)
      e.target.elements.usernameInput.value="";
      e.target.elements.passwordInput.value="";
      setFeedback(response.data);
    } catch (error) {
        console.log(error);
        e.target.elements.usernameInput.value="";
        e.target.elements.passwordInput.value="";
        setFeedback(error.response.data);
    }
  };
  return (
    <div>
      <h2>Registration</h2>
      <form onSubmit={handleRegister}>
        <label>
          Username:
          <input type="text" name='usernameInput' />
        </label>
        <br />
        <label>
          Password:
          <input type="password" name='passwordInput' />
        </label>
        <br />
        <button type="submit">Register</button>
      </form>
      <div>Already have an account? <Link to="/login">Login here!</Link></div>
      {feedback && (feedback==="This username is already taken. Please choose a different username." || feedback==="You need to include both a username and a password") && <p style={{color:'red'}}>{feedback}</p>}
      {feedback && feedback=== "User Registered Successfully" && <p style={{color:'green'}}>{feedback}</p>}
    </div>
  );
};

export default RegistrationComponent;