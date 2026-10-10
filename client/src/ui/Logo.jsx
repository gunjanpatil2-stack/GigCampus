import React from 'react';

export function Logo({ go }) {
  return (
    <button className="flex items-center gap-2 text-left" onClick={() => go('Home')}>
      <span className="grid size-9 place-items-center rounded-xl bg-violet-700 text-lg font-black text-white">G</span>
      <span className="text-xl font-extrabold tracking-tight">
        Gig<span className="text-violet-700">Campus</span>
      </span>
    </button>
  );
}
