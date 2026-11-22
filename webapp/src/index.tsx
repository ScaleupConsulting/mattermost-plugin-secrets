import manifest from 'manifest';
import type {Store} from 'redux';

import type {Post} from '@mattermost/types/posts';
import type {GlobalState} from '@mattermost/types/store';

import {getChannel} from 'mattermost-redux/selectors/entities/channels';
import {getConfig} from 'mattermost-redux/selectors/entities/general';
import {getCurrentUserId} from 'mattermost-redux/selectors/entities/users';

import type {PluginRegistry} from 'types/mattermost-webapp';

import {setSiteURL} from './client';
import SecretModal from './components/secret_modal';
import SecretPost from './components/secret_post';
import {openComposer} from './events';
import {ensureKeyPair} from './keys';

import en from '../i18n/en.json';

const postType = 'custom_secret';

export default class Plugin {
    /**
     * Registers the composer, the secret post renderer and the /secret and edit hooks.
     * @param registry - the webapp plugin registry
     * @param store - the webapp Redux store
     */
    public async initialize(registry: PluginRegistry, store: Store<GlobalState>) {
        setSiteURL(getConfig(store.getState()).SiteURL);

        // Plugins load before login on the login page, so set up the key whenever a user appears.
        let keyedUserId = '';

        /** Generates and registers this browser's key the first time each user is seen. */
        const setupKey = () => {
            const userId = getCurrentUserId(store.getState());
            if (userId && userId !== keyedUserId) {
                keyedUserId = userId;
                // eslint-disable-next-line no-console
                ensureKeyPair(userId).catch((e) => console.error(`${manifest.id}: key setup failed`, e));
            }
        };
        setupKey();
        store.subscribe(setupKey);

        registry.registerTranslations((locale: string) => (locale === 'en' ? en : {}));
        registry.registerRootComponent(SecretModal);
        registry.registerPostTypeComponent(postType, SecretPost);

        registry.registerSlashCommandWillBePostedHook((message: string, args: {channel_id: string; root_id?: string}) => {
            const match = (/^\/secret(?:\s+([\s\S]*))?$/).exec(message.trim());
            if (!match) {
                return {message, args};
            }
            const channel = getChannel(store.getState(), args.channel_id);
            if (!channel || (channel.type !== 'D' && channel.type !== 'G')) {
                return {error: {message: 'Secret messages can only be sent in direct and group messages.'}};
            }
            openComposer({channelId: args.channel_id, rootId: args.root_id ?? '', text: match[1] ?? ''});
            return {};
        });

        registry.registerMessageWillBeUpdatedHook(async (post: Partial<Post>, oldPost: Post) => {
            if (String(oldPost.type) === postType || String(post.type) === postType) {
                return {error: {message: 'Secret messages cannot be edited. Delete it and send a new one.'}};
            }
            return {post: post as Post};
        });
    }
}

declare global {
    interface Window {
        registerPlugin(pluginId: string, plugin: Plugin): void;
    }
}

window.registerPlugin(manifest.id, new Plugin());
