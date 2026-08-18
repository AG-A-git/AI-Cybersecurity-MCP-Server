import React from "react";

function Table({ headers = [], rows = [], actions }) {
  return (
    <div className="table-responsive">
      <table className="table table-striped table-bordered">

        <thead>
          <tr>
            {headers.map((header, index) => (
              <th key={index}>{header}</th>
            ))}

            {actions && <th>Actions</th>}
          </tr>
        </thead>

        <tbody>
          {rows.length > 0 ? (
            rows.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {headers.map((header, columnIndex) => (
                  <td key={columnIndex}>
                    {row[header]}
                  </td>
                ))}

                {actions && (
                  <td>
                    {actions(row, rowIndex)}
                  </td>
                )}
              </tr>
            ))
          ) : (
            <tr>
              <td
                colSpan={headers.length + (actions ? 1 : 0)}
                className="text-center"
              >
                No data available.
              </td>
            </tr>
          )}
        </tbody>

      </table>
    </div>
  );
}

export default Table;