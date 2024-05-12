import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import axios from '../utils/AxiosWithCredentials.ts';
import { hostname } from '../utils/utils.ts';
import { useNavigate } from 'react-router-dom';

const LoginComponent = () => {
  const navigate = useNavigate();
  const [feedback, setFeedback]= useState("");
  const [isLoggedIn, setIsLoggedIn] = useState<boolean | null>(null);
  const [username, setUsername] = useState<string | null>(null)
  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${hostname}/login`, {
        username,
        password:e.target.elements.passwordInput.value
      });
      console.log(response);
      e.target.elements.passwordInput.value="";
      setFeedback("Login Successful");
      setIsLoggedIn(true);
    } 
    catch (error) {
      setFeedback(error.response.data);
      e.target.elements.passwordInput.value="";
      setUsername("");

    }
  };
  const tokenVerify= async () => {
      try{
          const response= await axios.get(`${hostname}/verify-token`)
          console.log(response);
          setUsername(response.data.Username)
          setIsLoggedIn(true);
      }
      catch(error){
        console.log(error)
        setIsLoggedIn(false);
      }
    
  }

  React.useEffect(()=>{
    tokenVerify();
  }, []);

  const handleLogout = async (e) => {
    await axios.post(`${hostname}/logout`);
    setIsLoggedIn(false);
    setUsername("");
    setFeedback('');
  }

  // reset button 
  const handleRedirect = () => {
    navigate('/');
  };


  return (
    <div>
        {isLoggedIn?(
            <div>
            <h1>Welcome, {username}!</h1>
            <button onClick={handleLogout}>Logout</button>
            <button onClick={handleRedirect}>Go to Homepage</button>
            </div>

        ) :isLoggedIn===false? (<div>
        <h2>Login</h2>
        <form onSubmit={handleLogin}>
            <label>
            Username:
            <br />
            <input type="text" value={username===null? "": username} onChange={(e) => setUsername(e.target.value)} />
            </label>
            <br />
            <label>
            Password:
            <br />
            <input type="password" name="passwordInput"/>
            </label>
            <br />
            <button type="submit">Login</button>
        </form>
        <div>Don't have an account? <Link to="/register">Register here!</Link></div>
        {feedback && (feedback!=="Login Successful") && <p style={{color:'red'}}>{feedback}</p>}
        {feedback && feedback ==="Login Successful" && <p style={{color:'green'}}>{feedback}</p>}
        </div>):null
        }

    </div>
  );
};
export default LoginComponent;