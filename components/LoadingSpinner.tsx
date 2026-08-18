
import React from 'react';

export const LoadingSpinner: React.FC = () => {
    return (
        <div className="flex justify-center items-center p-4" role="status" aria-label="Loading">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-hacker-green"></div>
        </div>
    );
};

export default LoadingSpinner;
