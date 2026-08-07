import React from "react";

function DashboardCard({ title, value, icon }) {
  return (
    <div className="card shadow-sm h-100">
      <div className="card-body">

        <div className="d-flex justify-content-between align-items-center">

          <div>
            <h6 className="text-muted">
              {title}
            </h6>

            <h2>
              {value}
            </h2>
          </div>

          <div>
            <span className="fs-1">
              {icon}
            </span>
          </div>

        </div>

      </div>
    </div>
  );
}

export default DashboardCard;