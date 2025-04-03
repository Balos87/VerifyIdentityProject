import React, { useEffect, useState } from 'react';
import QuizCard from '../components/QuizCard';

interface Quiz {
  id: number;
  title: string;
  description: string;
}

const AccountPage = () => {
  const [quizzes, setQuizzes] = useState<Quiz[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchQuizzes = async () => {
      try {
        const response = await fetch(import.meta.env.VITE_API_URL);
        if (!response.ok) throw new Error('Failed to fetch quizzes');
        const data = await response.json();

        // if want more or less data, change the slice
        const mappedQuizzes = data.slice(0, 6).map((post: any) => ({
          id: post.id,
          title: post.title,
          description: post.body,
        }));

        setQuizzes(mappedQuizzes);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchQuizzes();
  }, []);

  return (
    <main className="min-h-screen flex flex-col items-center justify-center bg-gray-100 px-4">
      <h1 className="text-4xl font-bold mb-10">Account Page</h1>

      {loading && <p className="text-gray-500">Loading quizzes...</p>}
      {error && <p className="text-red-500">Error: {error}</p>}

      {/* <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6"> */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8 place-items-center">

      {quizzes.map((quiz, index) => (
        <QuizCard
          key={quiz.id}
          title={quiz.title}
          description={quiz.description}
          index={index}
        />
      ))}
      </div>
    </main>
  );
};

export default AccountPage;
