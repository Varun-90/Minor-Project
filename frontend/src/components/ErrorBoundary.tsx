import React from 'react';

interface State {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      message: error?.message || 'An unexpected application error occurred.',
    };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('NetShield UI ErrorBoundary caught:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-white text-neutral-950 flex items-center justify-center p-6">
          <div className="max-w-lg w-full border border-neutral-300 bg-white p-8">
            <p className="text-xs font-mono text-neutral-500 mb-2">Application Recovery</p>
            <h1 className="text-xl font-semibold tracking-tight text-neutral-950 mb-3">
              Something went wrong while rendering this view
            </h1>
            <p className="text-sm text-neutral-600 mb-6 break-words font-mono bg-neutral-50 border border-neutral-200 p-3">
              {this.state.message}
            </p>
            <button
              type="button"
              onClick={() => this.setState({ hasError: false, message: '' })}
              className="px-4 py-2 text-sm font-medium bg-neutral-950 text-white hover:bg-neutral-800 transition-colors cursor-pointer"
            >
              Retry View
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
