import React from 'react';
import { motion } from 'framer-motion';

interface QuizCardProps {
  title: string;
  description: string;
  index?: number;
}

const QuizCard: React.FC<QuizCardProps> = ({ title, description, index }) => {
  return (
    <motion.div
      className="bg-white rounded-2xl shadow-lg p-8 w-full max-w-sm text-center hover:scale-105 transition-transform duration-300"
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut', delay: (index ?? 0) * 0.1 }}
      whileHover={{ scale: 1.05 }}
    >
      <h2 className="text-xl font-bold text-gray-800 mb-2">{title}</h2>
      <p className="text-gray-500 text-sm mb-6">{description}</p>
      <button className="px-6 py-2 bg-blue-500 text-white rounded-lg shadow hover:bg-blue-600 transition">
        Go to test
      </button>
    </motion.div>
  );
};

export default QuizCard;
