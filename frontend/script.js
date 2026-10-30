document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const fileSummary = document.getElementById('fileSummary');
    const sendBtn = document.getElementById('sendBtn');
    const resultArea = document.getElementById('resultArea');
    const transferCodeDisplay = document.getElementById('transferCode');
    const receiveCodeInput = document.getElementById('receiveCode');
    const receiveBtn = document.getElementById('receiveBtn');
    const downloadArea = document.getElementById('downloadArea');

    // List of prohibited executable, script, and malware-associated extensions
    const DANGEROUS_EXTENSIONS = new Set([
        '.exe', '.dll', '.so', '.dylib', '.com', '.scr', '.pif', '.cpl', '.msi', '.msp', '.mst',
        '.sys', '.drv', '.ocx', '.gadget', '.hta', '.efi',
        '.bat', '.cmd', '.vbs', '.vbe', '.wsf', '.wsh', '.ws', '.wsc',
        '.ps1', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.psm1', '.psd1',
        '.reg', '.inf', '.job',
        '.sh', '.bash', '.zsh', '.csh', '.ksh', '.bin', '.run', '.out', '.elf',
        '.app', '.dmg', '.pkg', '.deb', '.rpm',
        '.php', '.php3', '.php4', '.php5', '.phtml', '.phar', '.pht', '.phps',
        '.jsp', '.jspx', '.jspa', '.asp', '.aspx', '.asa', '.asax', '.ascx', '.ashx', '.asmx',
        '.cgi', '.pl', '.py', '.pyc', '.pyo', '.pyd', '.rb',
        '.jar', '.class', '.apk', '.dex', '.xapk',
        '.crx', '.xpi', '.iso', '.img', '.vhd', '.vhdx',
        '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm', '.potm', '.ppam', '.ppsm', '.sldm'
    ]);

    // Prohibited MIME types for executables and scripts
    const DANGEROUS_MIME_TYPES = new Set([
        'application/x-msdownload',
        'application/x-msdos-program',
        'application/x-executable',
        'application/x-sharedlib',
        'application/x-pie-executable',
        'application/x-sh',
        'application/x-bash',
        'application/x-csh',
        'application/x-shar',
        'application/x-shellscript',
        'application/x-bat',
        'application/x-msdos-batch',
        'application/x-cmd',
        'application/x-msi',
        'application/x-apple-diskimage',
        'application/vnd.microsoft.portable-executable',
        'application/x-elf',
        'application/x-mach-binary',
        'application/x-dosexec',
        'application/x-php',
        'application/x-httpd-php',
        'text/x-shellscript',
        'text/x-php',
        'text/x-python',
        'text/x-perl',
        'text/x-ruby',
        'application/java-archive',
        'application/vnd.android.package-archive'
    ]);

    function formatFileSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    /**
     * Sanitizes and validates a file before upload.
     */
    function checkFileSafety(file) {
        if (!file) return { safe: false, message: 'No file selected.' };

        const fileName = file.name || '';

        // Check for Unicode bidirectional override spoofing (RLO attacks)
        if (/[\u202A-\u202E\u2066-\u2069]/.test(fileName)) {
            return {
                safe: false,
                message: `Security warning for "${fileName}": Filename contains prohibited bidirectional characters (RLO attack).`
            };
        }

        // Check file extensions (including double-extension cloaking)
        const parts = fileName.toLowerCase().split('.');
        if (parts.length > 1) {
            const finalExt = '.' + parts[parts.length - 1];
            if (DANGEROUS_EXTENSIONS.has(finalExt)) {
                return {
                    safe: false,
                    message: `Security warning: File "${fileName}" has prohibited extension '${finalExt}'. Executable and potentially malicious files cannot be uploaded.`
                };
            }

            for (let i = 1; i < parts.length - 1; i++) {
                const middleExt = '.' + parts[i];
                if (DANGEROUS_EXTENSIONS.has(middleExt)) {
                    return {
                        safe: false,
                        message: `Security warning: Disguised executable extension '${middleExt}' detected in "${fileName}".`
                    };
                }
            }
        }

        // Check MIME type
        const mimeType = (file.type || '').toLowerCase().trim();
        if (DANGEROUS_MIME_TYPES.has(mimeType)) {
            return {
                safe: false,
                message: `Security warning: File "${fileName}" has prohibited MIME type '${mimeType}'.`
            };
        }

        return { safe: true };
    }

    // Immediate sanitization check upon file selection & summary display
    fileInput.addEventListener('change', () => {
        const files = Array.from(fileInput.files || []);
        if (files.length === 0) {
            fileSummary.classList.add('hidden');
            fileSummary.textContent = '';
            return;
        }

        for (const file of files) {
            const check = checkFileSafety(file);
            if (!check.safe) {
                alert(check.message);
                fileInput.value = '';
                fileSummary.classList.add('hidden');
                fileSummary.textContent = '';
                resultArea.classList.add('hidden');
                return;
            }
        }

        const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
        fileSummary.classList.remove('hidden');
        if (files.length === 1) {
            fileSummary.textContent = `1 file: ${files[0].name} (${formatFileSize(totalBytes)})`;
        } else {
            fileSummary.textContent = `${files.length} files selected (${formatFileSize(totalBytes)})`;
        }
    });

    sendBtn.addEventListener('click', async () => {
        const files = Array.from(fileInput.files || []);
        if (files.length === 0) return alert('Select at least one file first!');

        // Pre-upload sanitization check
        for (const file of files) {
            const check = checkFileSafety(file);
            if (!check.safe) {
                alert(check.message);
                fileInput.value = '';
                fileSummary.classList.add('hidden');
                resultArea.classList.add('hidden');
                return;
            }
        }

        sendBtn.disabled = true;
        sendBtn.textContent = 'Zipping & Uploading...';

        try {
            const formData = new FormData();
            for (const file of files) {
                formData.append('files', file);
            }

            const response = await fetch('/api/transfers/upload', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Upload failed');

            transferCodeDisplay.textContent = data.transferCode;
            resultArea.classList.remove('hidden');
        } catch (error) {
            alert(error.message);
        } finally {
            sendBtn.disabled = false;
            sendBtn.textContent = 'Upload & Get Code';
        }
    });

    async function triggerDownload(url, defaultFilename) {
        const response = await fetch(url);
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.message || 'Download failed');
        }

        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = defaultFilename || 'file';
        if (contentDisposition) {
            const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
            const matches = filenameRegex.exec(contentDisposition);
            if (matches != null && matches[1]) {
                filename = matches[1].replace(/['"]/g, '').trim();
                filename = decodeURIComponent(filename);
            }
        }

        const blob = await response.blob();
        const blobUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(blobUrl);
        document.body.removeChild(a);
    }

    receiveBtn.addEventListener('click', async () => {
        const code = receiveCodeInput.value.trim();
        if (code.length !== 6) return alert('Enter a 6-digit code');

        receiveBtn.disabled = true;
        receiveBtn.textContent = 'Checking code...';
        downloadArea.classList.add('hidden');
        downloadArea.innerHTML = '';

        try {
            const infoRes = await fetch(`/api/transfers/${code}/info`);
            if (!infoRes.ok) {
                const err = await infoRes.json().catch(() => ({}));
                throw new Error(err.message || 'Invalid or expired code');
            }

            const info = await infoRes.json();

            // If single file, immediately uncompress and download
            if (info.fileCount === 1) {
                receiveBtn.textContent = 'Unzipping & Downloading...';
                const fileObj = info.files && info.files[0];
                await triggerDownload(`/api/transfers/${code}`, fileObj?.original_name);
            } else {
                // Multi-file transfer: render unzipped download list
                renderMultiFileDownloadArea(code, info);
            }
        } catch (error) {
            alert(error.message);
        } finally {
            receiveBtn.disabled = false;
            receiveBtn.textContent = 'Download File';
        }
    });

    function renderMultiFileDownloadArea(code, info) {
        downloadArea.innerHTML = '';
        downloadArea.classList.remove('hidden');

        const header = document.createElement('div');
        header.className = 'download-area-header';
        header.textContent = `${info.fileCount} files ready:`;
        downloadArea.appendChild(header);

        info.files.forEach((file) => {
            const item = document.createElement('div');
            item.className = 'file-item';

            const infoDiv = document.createElement('div');
            infoDiv.className = 'file-info';

            const nameDiv = document.createElement('div');
            nameDiv.className = 'file-name';
            nameDiv.textContent = file.original_name;
            nameDiv.title = file.original_name;

            const sizeDiv = document.createElement('div');
            sizeDiv.className = 'file-size';
            sizeDiv.textContent = formatFileSize(file.size);

            infoDiv.appendChild(nameDiv);
            infoDiv.appendChild(sizeDiv);

            const dlBtn = document.createElement('button');
            dlBtn.className = 'file-dl-btn';
            dlBtn.textContent = 'Download';
            dlBtn.addEventListener('click', async () => {
                dlBtn.disabled = true;
                dlBtn.textContent = 'Unzipping...';
                try {
                    await triggerDownload(
                        `/api/transfers/${code}?file=${encodeURIComponent(file.original_name)}`,
                        file.original_name
                    );
                } catch (err) {
                    alert(err.message);
                } finally {
                    dlBtn.disabled = false;
                    dlBtn.textContent = 'Download';
                }
            });

            item.appendChild(infoDiv);
            item.appendChild(dlBtn);
            downloadArea.appendChild(item);
        });

        const dlAllBtn = document.createElement('button');
        dlAllBtn.className = 'dl-all-btn';
        dlAllBtn.textContent = `Download All (${info.fileCount} files)`;
        dlAllBtn.addEventListener('click', async () => {
            dlAllBtn.disabled = true;
            dlAllBtn.textContent = 'Downloading all unzipped files...';
            try {
                for (const file of info.files) {
                    await triggerDownload(
                        `/api/transfers/${code}?file=${encodeURIComponent(file.original_name)}`,
                        file.original_name
                    );
                    // Short pause between file triggers so browser downloads smoothly
                    await new Promise(r => setTimeout(r, 400));
                }
            } catch (err) {
                alert(err.message);
            } finally {
                dlAllBtn.disabled = false;
                dlAllBtn.textContent = `Download All (${info.fileCount} files)`;
            }
        });

        downloadArea.appendChild(dlAllBtn);
    }
});
