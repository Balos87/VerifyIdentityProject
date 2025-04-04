import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const LoginCard = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const correctUsername = import.meta.env.VITE_ADMIN_LOGIN;
    const correctPassword = import.meta.env.VITE_ADMIN_PASSWORD;

    if (email === correctUsername && password === correctPassword) {
      localStorage.setItem('isLoggedIn', 'true');
      navigate('/account');
    } else {
      setError('Invalid email or password');
    }
  };

  return (
    <div className="flex min-h-full flex-1 flex-col justify-center px-6 py-12 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-sm">
        <img
          alt="Learnpoint logo"
          src="https://lh3.googleusercontent.com/p/AF1QipMrmgsdZgX4h2A34cgnKOWqz7Uu0pPcwxej88Av=s680-w680-h510"
          className="mx-auto h-10 w-auto"
        />
        <h2 className="mt-10 text-center text-xl/9 font-bold tracking-tight text-gray-900">
          Sign in to your account
        </h2>
      </div>

      <div className="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-900">
              Email
            </label>
            <div className="mt-2">
              <input
                id="email"
                name="email"
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="block w-full rounded-md bg-white px-3 py-1.5 text-base text-gray-900 outline-1 -outline-offset-1 outline-gray-300 placeholder:text-gray-400 focus:outline-2 focus:-outline-offset-2 focus:outline-indigo-600 sm:text-sm"
              />
            </div>
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-900">
              Password
            </label>
            <div className="mt-2">
              <input
                id="password"
                name="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="block w-full rounded-md bg-white px-3 py-1.5 text-base text-gray-900 outline-1 -outline-offset-1 outline-gray-300 placeholder:text-gray-400 focus:outline-2 focus:-outline-offset-2 focus:outline-indigo-600 sm:text-sm"
              />
            </div>
          </div>

          {error && <p className="text-sm text-red-600 font-medium">{error}</p>}

          <div>
            <button
              type="submit"
              className="flex w-full justify-center rounded-md bg-cyan-600 px-3 py-1.5 text-sm font-semibold text-white shadow-xs hover:bg-cyan-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
            >
              Sign in
            </button>
          </div>
        </form>

        <p className="mt-5 text-center text-sm text-gray-500">
          <a href="#" className="font-semibold text-cyan-900 hover:text-indigo-500">
            Register
          </a>
        </p>
        <div className="text-sm text-center mt-2">
          <a href="#" className="font-semibold text-cyan-900 hover:text-indigo-500">
            Forgot password?
          </a>
        </div>
      </div>
    </div>
  );
};

export default LoginCard;
