document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const sendBtn = document.getElementById('sendBtn');
    const resultArea = document.getElementById('resultArea');
    const transferCodeDisplay = document.getElementById('transferCode');
    const receiveCodeInput = document.getElementById('receiveCode');
    const receiveBtn = document.getElementById('receiveBtn');

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
                message: 'Security warning: Filename contains prohibited bidirectional characters (RLO attack).'
            };
        }

        // Check file extensions (including double-extension cloaking)
        const parts = fileName.toLowerCase().split('.');
        if (parts.length > 1) {
            const finalExt = '.' + parts[parts.length - 1];
            if (DANGEROUS_EXTENSIONS.has(finalExt)) {
                return {
                    safe: false,
                    message: `Security warning: File type '${finalExt}' is prohibited. Executable and potentially malicious files cannot be uploaded.`
                };
            }

            for (let i = 1; i < parts.length - 1; i++) {
                const middleExt = '.' + parts[i];
                if (DANGEROUS_EXTENSIONS.has(middleExt)) {
                    return {
                        safe: false,
                        message: `Security warning: Disguised executable extension '${middleExt}' detected in filename.`
                    };
                }
            }
        }

        // Check MIME type
        const mimeType = (file.type || '').toLowerCase().trim();
        if (DANGEROUS_MIME_TYPES.has(mimeType)) {
            return {
                safe: false,
                message: `Security warning: File type '${mimeType}' is prohibited for security reasons.`
            };
        }

        return { safe: true };
    }

    // Immediate sanitization check upon file selection
    fileInput.addEventListener('change', () => {
        const file = fileInput.files[0];
        if (!file) return;

        const check = checkFileSafety(file);
        if (!check.safe) {
            alert(check.message);
            fileInput.value = '';
            resultArea.classList.add('hidden');
        }
    });

    sendBtn.addEventListener('click', async () => {
        const file = fileInput.files[0];
        if (!file) return alert('Select a file first!');

        // Pre-upload sanitization check
        const check = checkFileSafety(file);
        if (!check.safe) {
            alert(check.message);
            fileInput.value = '';
            resultArea.classList.add('hidden');
            return;
        }

        sendBtn.disabled = true;
        sendBtn.textContent = 'Uploading...';

        try {
            const formData = new FormData();
            formData.append('file', file);

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

    receiveBtn.addEventListener('click', async () => {
        const code = receiveCodeInput.value.trim();
        if (code.length !== 6) return alert('Enter a 6-digit code');

        receiveBtn.disabled = true;
        receiveBtn.textContent = 'Downloading...';

        try {
            const response = await fetch(`/api/transfers/${code}`);
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.message || 'Download failed');
            }

            // Extract filename safely
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = 'file';
            if (contentDisposition) {
                const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                const matches = filenameRegex.exec(contentDisposition);
                if (matches != null && matches[1]) {
                    filename = matches[1].replace(/['"]/g, '').trim();
                    filename = decodeURIComponent(filename);
                }
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');  
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (error) {
            alert(error.message);
        } finally {
            receiveBtn.disabled = false;
            receiveBtn.textContent = 'Download File';
        }
    });
});
