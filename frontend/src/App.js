import './App.css'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Home from './components/pages/Home'
import Header from './components/pages/Header/Header';
import Footer from './components/pages/Footer/Footer';


function App() {
    return (
        <>
            <Router>
				<Header/>
                <Routes>
                    <Route exact path="/" element={<Home/>} />
                </Routes>
				<Footer/>
            </Router>
        </>
    );
}

export default App;
