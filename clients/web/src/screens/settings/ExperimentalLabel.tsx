import { EXPERIMENTAL_NOTE } from './integrationsData'

/** The chip every enable surface shows for an experimental connector. It has no
 *  close or "mark as supported" control: the status comes from integrationsData. */
export function ExperimentalChip() {
  return (
    <span className="chip int-exp" title={EXPERIMENTAL_NOTE}>
      Experimental
    </span>
  )
}

/** The same status in words, for the forms that turn a connector on. */
export function ExperimentalNote() {
  return (
    <p className="int-exp-note" role="note">
      {EXPERIMENTAL_NOTE}
    </p>
  )
}
