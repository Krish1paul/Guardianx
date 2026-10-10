import { useMutation } from '@tanstack/react-query';
import { scanAPI } from '@/lib/api';
import type { FileScanResponse, MessageScanRequest, MessageScanResponse, URLScanResponse } from '@/types/api';

export function useScan() {
  return useMutation<URLScanResponse, Error, { url: string }>({
    mutationFn: (data) => scanAPI.analyze(data),
  });
}

export function useMessageScan() {
  return useMutation<MessageScanResponse, Error, MessageScanRequest>({
    mutationFn: (data) => scanAPI.analyzeMessage(data),
  });
}

export function useFileScan() {
  return useMutation<FileScanResponse, Error, File>({
    mutationFn: (file) => scanAPI.analyzeFile(file),
  });
}

