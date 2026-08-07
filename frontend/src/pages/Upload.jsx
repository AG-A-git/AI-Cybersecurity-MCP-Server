import React, { useState } from "react";

function Upload() {
  const [selectedFile, setSelectedFile] = useState(null);

  // Handle normal file selection
  const handleFileChange = (event) => {
    const file = event.target.files[0];

    if (file) {
      setSelectedFile(file);
    }
  };

  // Handle ZIP file selection
  const handleZipChange = (event) => {
    const file = event.target.files[0];

    if (file) {
      setSelectedFile(file);
    }
  };

  // Handle drag and drop
  const handleDrop = (event) => {
    event.preventDefault();

    const file = event.dataTransfer.files[0];

    if (file) {
      setSelectedFile(file);
    }
  };

  const handleDragOver = (event) => {
    event.preventDefault();
  };

  // Upload button
  const handleUpload = () => {
    if (!selectedFile) {
      alert("Please select a file first.");
      return;
    }

    alert(`File "${selectedFile.name}" is ready for upload.`);
  };

  return (
    <div
      style={{
        maxWidth: "900px",
        margin: "40px auto",
        padding: "20px",
        fontFamily: "Arial, sans-serif",
      }}
    >
      {/* Page Heading */}
      <h1 style={{ marginBottom: "10px" }}>
        Upload Security Project
      </h1>

      <p style={{ color: "#555", marginBottom: "25px" }}>
        Upload your source code for vulnerability scanning.
      </p>

      {/* Drag and Drop Area */}
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        style={{
          border: "2px dashed #777",
          borderRadius: "10px",
          padding: "40px 20px",
          textAlign: "center",
          backgroundColor: "#f8f9fa",
          marginBottom: "25px",
        }}
      >
        <div style={{ fontSize: "50px", marginBottom: "15px" }}>
          📁
        </div>

        <h3 style={{ marginBottom: "10px" }}>
          Drag & Drop Your File Here
        </h3>

        <p style={{ color: "#666" }}>
          or choose a file from your computer
        </p>

        {/* Buttons */}
        <div
          style={{
            display: "flex",
            justifyContent: "center",
            gap: "15px",
            marginTop: "20px",
            flexWrap: "wrap",
          }}
        >
          {/* Choose File */}
          <label
            style={{
              display: "inline-block",
              cursor: "pointer",
            }}
          >
            <input
              type="file"
              onChange={handleFileChange}
              style={{ display: "none" }}
            />

            <span
              style={{
                display: "inline-block",
                padding: "10px 20px",
                backgroundColor: "#0d6efd",
                color: "white",
                borderRadius: "6px",
                cursor: "pointer",
              }}
            >
              Choose File
            </span>
          </label>

          {/* Choose ZIP */}
          <label
            style={{
              display: "inline-block",
              cursor: "pointer",
            }}
          >
            <input
              type="file"
              accept=".zip"
              onChange={handleZipChange}
              style={{ display: "none" }}
            />

            <span
              style={{
                display: "inline-block",
                padding: "10px 20px",
                backgroundColor: "#6c757d",
                color: "white",
                borderRadius: "6px",
                cursor: "pointer",
              }}
            >
              Choose ZIP
            </span>
          </label>
        </div>
      </div>

      {/* Selected File */}
      <div
        style={{
          padding: "20px",
          border: "1px solid #ddd",
          borderRadius: "8px",
          backgroundColor: "white",
          marginBottom: "20px",
        }}
      >
        <h3 style={{ marginBottom: "10px" }}>
          Selected File
        </h3>

        {selectedFile ? (
          <p style={{ margin: 0 }}>
            📄 <strong>{selectedFile.name}</strong>
          </p>
        ) : (
          <p style={{ color: "#777", margin: 0 }}>
            No file selected
          </p>
        )}
      </div>

      {/* Upload Button */}
      <button
        type="button"
        onClick={handleUpload}
        style={{
          padding: "12px 30px",
          backgroundColor: "#198754",
          color: "white",
          border: "none",
          borderRadius: "6px",
          fontSize: "16px",
          cursor: "pointer",
        }}
      >
        Upload
      </button>
    </div>
  );
}

export default Upload;