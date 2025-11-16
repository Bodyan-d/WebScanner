import React from "react";

export default function Tabs({ tabs, defaultTab }) {
  const [active, setActive] = React.useState(defaultTab || (tabs[0] && tabs[0].id));

  React.useEffect(() => {
    if (!active && tabs[0]) setActive(tabs[0].id);
  }, [tabs]);

  const activeTab = tabs.find(t => t.id === active) || tabs[0];

  return (
    <div>
      <div className="tabs-row">
        {tabs.map(t => (
          <button
            key={t.id}
            className={`tab-btn ${t.id === active ? "active" : ""}`}
            onClick={() => setActive(t.id)}
          >
            {t.title}
          </button>
        ))}
      </div>
      <div style={{marginTop:16}}>
        {activeTab ? activeTab.content : null}
      </div>
    </div>
  );
}
