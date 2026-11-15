import manifest from 'manifest';

export const openEvent = `${manifest.id}:open-composer`;

export type OpenDetail = {channelId: string; rootId: string; text: string};

/**
 * Asks the root-mounted composer modal to open; a DOM event avoids a Redux reducer for one flag.
 * @param detail - where to send and any text typed after /secret
 */
export function openComposer(detail: OpenDetail) {
    window.dispatchEvent(new CustomEvent<OpenDetail>(openEvent, {detail}));
}
