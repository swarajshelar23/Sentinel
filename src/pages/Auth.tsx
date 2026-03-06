import React, { useState } from 'react';
import axios from 'axios';
import { motion } from 'motion/react';
import { Terminal, Lock, UserPlus, LogIn } from 'lucide-react';

export default function Auth({ onLogin }: { onLogin: (user: any) => void }) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const { data } = await axios.post(endpoint, { username, password });
      
      if (isLogin) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        onLogin(data.user);
      } else {
        setIsLogin(true);
        setError('Registration successful. Please login.');
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto mt-20">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="border-2 border-[#141414] p-8 bg-white shadow-[8px_8px_0px_0px_rgba(20,20,20,1)]"
      >
        <div className="flex items-center gap-2 mb-8">
          <Terminal className="w-6 h-6" />
          <h2 className="font-mono font-bold text-2xl uppercase">
            {isLogin ? 'SYSTEM_LOGIN' : 'CREATE_ACCOUNT'}
          </h2>
        </div>

        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-2 mb-6 font-mono text-xs">
            ERROR: {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block font-mono text-xs font-bold uppercase mb-2">Username</label>
            <div className="relative">
              <input 
                type="text" 
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full border border-[#141414] p-3 pl-10 focus:outline-none focus:ring-2 focus:ring-[#141414]/20"
                required
              />
              <Terminal className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 opacity-50" />
            </div>
          </div>

          <div>
            <label className="block font-mono text-xs font-bold uppercase mb-2">Password</label>
            <div className="relative">
              <input 
                type="password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full border border-[#141414] p-3 pl-10 focus:outline-none focus:ring-2 focus:ring-[#141414]/20"
                required
              />
              <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 opacity-50" />
            </div>
          </div>

          <button 
            type="submit"
            disabled={loading}
            className="w-full bg-[#141414] text-[#E4E3E0] py-4 font-bold flex items-center justify-center gap-2 hover:opacity-90 disabled:opacity-50 transition-opacity"
          >
            {loading ? 'PROCESSING...' : (isLogin ? <><LogIn className="w-4 h-4" /> AUTHENTICATE</> : <><UserPlus className="w-4 h-4" /> REGISTER</>)}
          </button>
        </form>

        <button 
          onClick={() => setIsLogin(!isLogin)}
          className="w-full mt-6 font-mono text-xs underline underline-offset-4 opacity-70 hover:opacity-100"
        >
          {isLogin ? 'NEED_AN_ACCOUNT?' : 'ALREADY_HAVE_ACCESS?'}
        </button>
      </motion.div>
    </div>
  );
}
