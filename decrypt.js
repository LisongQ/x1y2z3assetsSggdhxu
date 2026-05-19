document.addEventListener('DOMContentLoaded', function () {
    const fileInput = document.getElementById('fileInput');
    const uploadArea = document.getElementById('uploadArea');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const passwordSection = document.getElementById('passwordSection');
    const passwordInput = document.getElementById('passwordInput');
    const decryptBtn = document.getElementById('decryptBtn');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');
    const downloadLink = document.getElementById('downloadLink');
    const detectedFormatEl = document.getElementById('detectedFormat');

    let selectedFile = null;

    uploadArea.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);

    ['dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, (e) => {
            e.preventDefault();
            if (eventName === 'dragover') uploadArea.classList.add('dragover');
            if (eventName === 'dragleave' || eventName === 'drop') uploadArea.classList.remove('dragover');
            if (eventName === 'drop' && e.dataTransfer.files.length > 0) {
                selectedFile = e.dataTransfer.files[0];
                displayFileInfo(selectedFile);
            }
        });
    });

    function displayFileInfo(file) {
        fileName.textContent = file.name;
        fileSize.textContent = `文件大小: ${formatFileSize(file.size)}`;
        fileInfo.classList.add('show');
        passwordSection.classList.add('show');
        decryptBtn.disabled = false;
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024, sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function decryptFile(file, password) {
        const fileBuffer = await readFileAsArrayBuffer(file);
        const encryptedData = new Uint8Array(fileBuffer);

        if (encryptedData.length < 31) throw new Error("文件太小或格式不正确");

        const salt = encryptedData.slice(3, 19);
        const iv = encryptedData.slice(19, 31);
        const ciphertext = encryptedData.slice(31);

        const finalPassword = password || "default";
        const passwordKey = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(finalPassword),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        const aesKey = await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
            passwordKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        const decryptedArrayBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            ciphertext
        );

        const extension = detectFileExtension(new Uint8Array(decryptedArrayBuffer));
        return {
            arrayBuffer: decryptedArrayBuffer,
            blob: new Blob([decryptedArrayBuffer]),
            extension: extension
        };
    }

    function detectFileExtension(uint8Array) {
        const header = uint8Array;
        const signatures = {
            '.png': [0x89, 0x50, 0x4E, 0x47],
            '.jpg': [0xFF, 0xD8, 0xFF, 0xE0],
            '.jpeg': [0xFF, 0xD8, 0xFF, 0xE0],
            '.jfif': [0xFF, 0xD8, 0xFF, 0xE1],
            '.webp': [0x52, 0x49, 0x46, 0x46],
            '.gif': [0x47, 0x49, 0x46, 0x38],
            '.bmp': [0x42, 0x4D],
            '.tiff': [0x49, 0x49, 0x2A, 0x00],
            '.tif': [0x4D, 0x4D, 0x00, 0x2A],
            '.pdf': [0x25, 0x50, 0x44, 0x46],
            '.doc': [0xD0, 0xCF, 0x11, 0xE0],
            '.docx': [0x50, 0x4B, 0x03, 0x04],
            '.xlsx': [0x50, 0x4B, 0x03, 0x04],
            '.pptx': [0x50, 0x4B, 0x03, 0x04],
            '.zip': [0x50, 0x4B, 0x03, 0x04],
            '.rar': [0x52, 0x61, 0x72, 0x21],
            '.7z': [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            '.mp3': [0x49, 0x44, 0x33],
            '.wav': [0x52, 0x49, 0x46, 0x46],
            '.mp4': [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70],
            '.avi': [0x52, 0x49, 0x46, 0x46],
            '.html': [0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54],
            '.xml': [0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20],
            '.json': [0x7B],
        };

        for (const [ext, sig] of Object.entries(signatures)) {
            if (!sig) continue;
            if (sig.every((b, i) => header[i] === b)) {
                return ext;
            }
        }
        return '';
    }

    function readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = () => reject(new Error('读取文件失败'));
            reader.readAsArrayBuffer(file);
        });
    }

    function handleFileSelect(e) {
        if (e.target.files.length > 0) {
            selectedFile = e.target.files[0];
            displayFileInfo(selectedFile);
        }
    }

    decryptBtn.addEventListener('click', async function () {
        if (!selectedFile) return;
        loading.classList.add('show');
        result.classList.remove('show');
        decryptBtn.disabled = true;
        detectedFormatEl.textContent = "正在检测文件格式...";
        detectedFormatEl.style.color = "#2980b9";

        try {
            const { blob, extension } = await decryptFile(selectedFile, passwordInput.value);
            const originalFileNameBase = selectedFile.name.replace(/\.[^/.]+$/, "");
            let finalFileName = originalFileNameBase + (extension || "");

            if (extension) {
                detectedFormatEl.innerHTML =
                    `检测到文件格式: <strong>${extension.toUpperCase()}</strong> 文件`;
            } else {
                detectedFormatEl.textContent = "未能自动识别文件格式，将使用无扩展名下载。";
                detectedFormatEl.style.color = "#e67e22";
            }

            const downloadUrl = URL.createObjectURL(blob);
            downloadLink.href = downloadUrl;
            downloadLink.download = finalFileName;
            downloadLink.textContent = `下载 ${finalFileName}`;

            loading.classList.remove('show');
            result.classList.add('show');
        } catch (error) {
            alert(`解密失败: ${error.message}`);
            loading.classList.remove('show');
        }

        decryptBtn.disabled = false;
    });
});
