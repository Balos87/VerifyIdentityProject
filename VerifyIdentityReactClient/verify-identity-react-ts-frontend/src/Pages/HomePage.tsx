import LoginCard from "../components/LoginCard";

const HomePage = () => {
  return (
    <main className="min-h-screen bg-gradient-to-br from-cyan-50 to-white flex flex-col items-center justify-center px-4 py-16">
      <div className="max-w-xl w-full text-center mb-12">
        <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight text-gray-800 leading-tight mb-4">
          Welcome to <span className="text-cyan-600">LearnPoint AB</span>
        </h1>
        <p className="text-lg text-gray-600">
          Your platform to create, manage, and explore powerful quizzes.
        </p>
      </div>

      <LoginCard />
    </main>
  );
};

export default HomePage;
